import contextlib
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coldguardian import cli, feeds, notify, report, scan, wizard
from test_profiles import BASELINE, recorded


FIXTURES = Path(__file__).with_name('fixtures').resolve()
SCHEMA = FIXTURES.parents[1] / 'docs' / 'scan.schema.json'
JSON_TYPES = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool, 'null': type(None)}


def matches_contract(value, schema):
    if schema.keys() - {'$schema', 'title', 'const', 'enum', 'type', 'required', 'additionalProperties',
                        'properties', 'items', 'oneOf', 'minimum', 'maximum', 'minLength', 'format'}:
        raise AssertionError(f'Update the scan contract test for {schema}')
    types = schema.get('type', [])
    if isinstance(types, str):
        types = [types]
    if types and type(value) not in {JSON_TYPES[t] for t in types}:
        return False
    if 'const' in schema and value != schema['const'] or 'enum' in schema and value not in schema['enum']:
        return False
    if 'oneOf' in schema and sum(matches_contract(value, spec) for spec in schema['oneOf']) != 1:
        return False
    if isinstance(value, dict):
        fields = schema.get('properties', {})
        if set(schema.get('required', [])) - value.keys() or (
            schema.get('additionalProperties') is False and value.keys() - fields.keys()
        ):
            return False
        return all(matches_contract(value[key], fields[key]) for key in value.keys() & fields.keys())
    if isinstance(value, list) and 'items' in schema:
        return all(matches_contract(item, schema['items']) for item in value)
    if type(value) is int:
        return schema.get('minimum', value) <= value <= schema.get('maximum', value)
    if isinstance(value, str):
        if schema.get('format') == 'date-time':
            try:
                datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
            except ValueError:
                return False
        return len(value) >= schema.get('minLength', 0)
    return True


class ScanReportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config_path = self.root / 'config.json'
        self.properties = {
            'lan_cidr': '172.31.250.0/29',
            'hosts': {'scanner': '172.31.250.1', 'target': '172.31.250.2'},
            'output_dir': str(self.root),
        }
        self.enterContext(patch('socket.socket', side_effect=AssertionError('fixture scan opened a socket')))
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('fixture scan spawned a program')))
        self.enterContext(patch.dict(os.environ, clear=True))
        self.calls = []
        self.schema = json.loads(SCHEMA.read_text())

    def configure(self, baseline):
        self.config_path.write_text(json.dumps(self.properties))
        if baseline is not None:
            fingerprint = scan.config(self.properties)['_fingerprint']
            report.atomic_json(self.root / 'baseline.json', {'fingerprint': fingerprint, 'hosts': baseline})

    def scan_json(self, status, code, profile='quick', command=None):
        output = io.StringIO()
        if command is None:
            command = recorded(profile, self.calls)
        with patch.object(scan, 'command', command), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['scan', f'--{profile}', '--json', '--config', str(self.config_path)]), code)
        result = json.loads(output.getvalue())
        self.assertTrue(matches_contract(result, self.schema), result)
        self.assertEqual((result['status'], result['exit_code'], result['profile']), (status, code, profile))
        required = self.schema['properties']['findings']['items']['required']
        for finding in result['findings']:
            for field in required:
                self.assertIsInstance(finding[field], str)
                self.assertTrue(finding[field])
        return result

    def test_clean_and_incomplete_json(self):
        self.configure(BASELINE)
        clean = self.scan_json('clean', 0)
        self.assertEqual([f['category'] for f in clean['findings']], ['scan_summary'])
        incomplete = self.scan_json('incomplete', 2, command=lambda *_: b'incomplete XML')
        self.assertIn('host_discovery', {f['check'] for f in incomplete['findings']})

    def test_scan_reports_share_a_positive_scanner_peak_rss(self):
        self.configure(BASELINE)
        result = self.scan_json('clean', 0)
        peak = result.get('scanner_peak_rss_kib')
        self.assertIs(type(peak), int)
        self.assertGreater(peak, 0)
        record = json.loads((self.root / 'alerts.jsonl').read_text().splitlines()[-1])
        self.assertEqual(record['scanner_peak_rss_kib'], peak)
        for path in (self.root / 'latest.md', self.root / f'{record["timestamp"]}.md'):
            self.assertIn(f'Scanner peak RSS: {peak} KiB', path.read_text().splitlines())

    def test_bad_configuration_returns_one_json_document(self):
        result = self.scan_json('incomplete', 2)
        self.assertIsNone(result['timestamp'])
        self.assertIsNone(result['level'])
        self.assertEqual(result['findings'][0]['check'], 'configuration_or_io')

    def test_scan_uses_the_setup_config_when_no_path_is_supplied(self):
        self.configure(BASELINE)
        output = io.StringIO()
        with (patch.object(wizard, 'setup_config', return_value=self.config_path),
              patch.object(scan, 'command', recorded('quick', self.calls)),
              contextlib.redirect_stdout(output)):
            self.assertEqual(cli.main(['scan', '--json']), 0)
        self.assertTrue(matches_contract(json.loads(output.getvalue()), self.schema))

    def test_exact_host_scope_keeps_both_profiles_on_the_inventory(self):
        self.properties.update(lan_cidr='172.31.250.1/32', level='low')
        self.configure(BASELINE)
        for profile, status, code in (('quick', 'clean', 0), ('deep', 'bad', 1)):
            calls = []
            command = recorded(profile, calls, lambda xml: xml.replace('65535', '1000').replace('65533', '998'))
            with self.subTest(profile=profile):
                result = self.scan_json(status, code, profile=profile, command=command)
                self.assertEqual([args[1] for args, _ in calls], ['-sn', '-sT'])
                for args, _ in calls:
                    self.assertEqual(args[args.index('-oX') + 2:], ['172.31.250.1', '172.31.250.2'])
                self.assertEqual(result['findings'][0]['check'], 'scan_summary')
                self.assertEqual(result['findings'][0]['host_count'], 2)

    def test_exact_host_scope_requires_its_address_in_the_inventory(self):
        self.properties['lan_cidr'] = '172.31.250.3/32'
        self.configure(None)
        result = self.scan_json('incomplete', 2, profile='deep')
        self.assertEqual(result['findings'][0]['check'], 'configuration_or_io')
        self.assertEqual(self.calls, [])

    def test_status_checks_configuration_without_creating_scan_state(self):
        self.configure(None)
        output = io.StringIO()
        with (patch.object(wizard, 'setup_config', return_value=self.config_path),
              contextlib.redirect_stdout(output)):
            self.assertEqual(cli.main(['status', '--json']), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result, {'command': 'status', 'status': 'ok', 'exit_code': 0})
        schema = json.loads(SCHEMA.with_name('command-outcome.schema.json').read_text())
        self.assertTrue(matches_contract(result, schema))
        self.assertEqual(list(self.root.iterdir()), [self.config_path])

    def test_status_rejects_missing_and_invalid_configuration(self):
        for invalid in (None, 'not JSON', '[]', json.dumps(dict(self.properties, lan_cidr='172.31.250.0/31'))):
            if invalid is not None:
                self.config_path.write_text(invalid)
            with self.subTest(invalid=invalid), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['status', '--json', '--config', str(self.config_path)]), 2)
                self.assertEqual(json.loads(output.getvalue()), {'command': 'status', 'status': 'failed', 'exit_code': 2})

    def test_quick_reuses_approved_overlay_hosts_with_current_metadata(self):
        peer, missing = '100.90.12.2', '10.73.25.2'
        self.properties.update(
            hosts={'scanner': '172.31.250.1'},
            tailscale_peers=[peer, '100.90.12.3', 'fd7a:115c:a1e0::2'],
            wireguard_subnets=['10.73.25.0/30'],
        )
        self.configure({'172.31.250.1': [], peer: [22], missing: []})
        metadata = [(FIXTURES / name).read_bytes() for name in ('tailscale-status.json', 'ip-addr.json')]

        def command(args, timeout, input=None):
            self.assertEqual(args[-2:], ['-iL', '-'])
            self.assertEqual(input.decode().splitlines(), [peer, '172.31.250.1'])
            if args[1] == '-sT':
                self.assertEqual(args[args.index('-p') + 1], '22')
            return recorded('quick', self.calls, lambda xml: xml.replace('172.31.250.2', peer))(args, timeout)

        with patch.object(wizard, 'command', side_effect=metadata):
            result = self.scan_json('incomplete', 2, command=command)
        self.assertEqual(
            [(f['check'], f.get('ip')) for f in result['findings']],
            [('scan_summary', None), ('host_offline', missing)],
        )

    def test_unexpected_scan_failure_returns_incomplete_json(self):
        self.configure(BASELINE)
        def fail(*_):
            raise RuntimeError('private error detail')
        result = self.scan_json('incomplete', 2, command=fail)
        self.assertEqual(result['findings'][0]['check'], 'scan_error')
        self.assertNotIn('private error detail', str(result))

    def test_whole_second_timestamp_is_schema_valid(self):
        self.configure(BASELINE)
        with patch.object(report.datetime, 'datetime', wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 11, 20, tzinfo=timezone.utc)
            result = self.scan_json('clean', 0)
        self.assertEqual(result['timestamp'], '2026-11-20T00:00:00.000000Z')

    def test_scan_wires_findings_evidence_and_level_pages(self):
        auth_log = self.root / 'auth.log'
        auth_log.write_text(''.join(
            f'2026-11-20T00:0{minute}:{second:02d}+00:00 scanner sshd[123]: '
            f'Failed password for fixture from {ip} port 40000 ssh2\n'
            for ip, minute, second in (
                [('192.0.2.10', 0, i) for i in range(5)] + [('192.0.2.11', i * 2, 0) for i in range(5)]
            )
        ))
        feed = {'path': str(FIXTURES / 'feeds' / 'tweetfeed.csv')}
        self.properties.update(local_host='scanner', auth_paths=[str(auth_log)],
                               dns_paths=[str(FIXTURES / 'feeds' / 'pihole.log')], feed=feed,
                               tailscale_peers=['100.90.12.9'], level='high')
        self.configure(dict(BASELINE, **{'172.31.250.2': [22, 80]}))
        feeds.update_cache(self.root, feed)
        with patch.object(wizard, 'command', return_value=(FIXTURES / 'tailscale-status.json').read_bytes()) as peer_command, \
                patch.dict(os.environ, {notify.TOPIC_ENV: 'fixture'}), patch.object(notify, 'DIGEST_HOUR', 25), \
                patch.object(notify, 'send', return_value={'status': 'accepted'}) as send:
            result = self.scan_json('bad', 1, 'deep')
        peer_command.assert_called_once_with(['tailscale', 'status', '--json'], 10)
        findings = result['findings']
        self.assertEqual(result['level'], 'high')
        self.assertEqual([(f['client_ip'], f['count'], f['window_seconds']) for f in findings
                          if f['category'] == 'login_burst'], [('192.0.2.10', 5, 60)])
        self.assertEqual({(f['ip'], f['change']) for f in findings if f['category'] == 'peer_change'},
                         {('100.90.12.2', 'added'), ('100.90.12.3', 'added'),
                          ('fd7a:115c:a1e0::2', 'added'), ('100.90.12.9', 'removed')})
        self.assertEqual([(f['ip'], f['ports']) for f in findings if f['category'] == 'baseline_drift'],
                         [('172.31.250.2', [80])])
        self.assertEqual([(f['check'], f['ip'], f['port']) for f in findings if f['category'] == 'risky_service'],
                         [('ssh-password', '172.31.250.2', 22)])
        self.assertEqual([f['count'] for f in findings if f['category'] == 'dns_feed_match'], [1])
        page = send.call_args.args[0]
        self.assertIn('Failed sign-in burst on scanner from 192.0.2.10', page)
        self.assertIn('Tailscale peer 100.90.12.9 removed', page)
        self.assertIn('Previously approved ports no longer observed open on 172.31.250.2: 80', page)
        self.assertIn('Risky service on 172.31.250.2:22 (ssh-password)', page)
        self.assertTrue(any('matched the local feed' in item for item in page))
        markdown = (self.root / 'latest.md').read_text()
        for f in findings:
            if f['category'] in {'login_burst', 'peer_change', 'baseline_drift', 'risky_service', 'dns_feed_match'}:
                self.assertIn(f'[{f["check"]}, {f["evidence_id"]}]', markdown)
        self.assertNotIn('100.90.12.2', self.calls[-1][0])
        self.assertEqual(json.loads((self.root / 'state.json').read_text())['tailscale_peers'],
                         ['100.90.12.2', '100.90.12.3', 'fd7a:115c:a1e0::2'])

    def test_low_deep_scan_uses_top_ports_without_asserting_disappearance(self):
        self.properties['level'] = 'low'
        self.configure(dict(BASELINE, **{'172.31.250.2': [22, 80]}))
        def top_ports(text):
            return text.replace('count="65535"', 'count="1000"').replace('count="65533"', 'count="998"')
        result = self.scan_json('bad', 1, 'deep', command=recorded('deep', self.calls, top_ports))
        self.assertNotIn('baseline_drift', {f['category'] for f in result['findings']})
        args = self.calls[-1][0]
        self.assertEqual(args[args.index('--top-ports') + 1], '1000')

    def test_low_deep_scan_respects_explicit_ports_and_can_be_approved(self):
        self.properties.update(level='low', ports='443')
        self.configure(None)
        discovery = recorded('deep', self.calls)

        def command(args, timeout):
            if args[1] == '-sn':
                return discovery(args, timeout)
            self.calls.append((args, timeout))
            return (FIXTURES / 'profiles' / 'quick-ports.xml').read_bytes().replace(b'portid="22"', b'portid="443"')

        result = self.scan_json('incomplete', 2, 'deep', command)
        args = self.calls[-1][0]
        self.assertIn('-p', args)
        self.assertEqual(args[args.index('-p') + 1], '443')
        self.assertNotIn('--top-ports', args)
        self.assertIn('baseline_missing', {f['category'] for f in result['findings']})
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--config', str(self.config_path), '--approve-baseline']), 0)
        self.assertEqual(json.loads((self.root / 'baseline.json').read_text())['hosts']['172.31.250.2'], [443])

    def test_failed_peer_check_retains_prior_snapshot(self):
        self.properties['tailscale_peers'] = ['100.90.12.9']
        self.configure(BASELINE)
        report.atomic_json(self.root / 'state.json', {'tailscale_peers': ['100.90.12.10']})
        with patch.object(wizard, 'command', return_value=b'{"BackendState":"Stopped","Peer":null}'):
            result = self.scan_json('incomplete', 2)
        self.assertIn('tailscale_status', {f['check'] for f in result['findings']})
        self.assertNotIn('peer_change', {f['category'] for f in result['findings']})
        self.assertEqual(json.loads((self.root / 'state.json').read_text())['tailscale_peers'], ['100.90.12.10'])

    def test_schema_rejects_bad_status_and_unexpected_finding_fields(self):
        self.configure(BASELINE)
        result = self.scan_json('clean', 0)
        for update in ({'status': 'bad'}, {'level': 'invalid'},
                       {'findings': [dict(result['findings'][0], port=65536)]},
                       {'findings': [dict(result['findings'][0], hidden_field='unexpected')]}):
            self.assertFalse(matches_contract(dict(result, **update), self.schema), update)

    def test_corrupt_peer_snapshot_recovers_without_claiming_a_change(self):
        self.properties['tailscale_peers'] = ['100.90.12.9']
        self.configure(BASELINE)
        report.atomic_json(self.root / 'state.json', {'tailscale_peers': ['invalid']})
        with patch.object(wizard, 'command', return_value=(FIXTURES / 'tailscale-status.json').read_bytes()):
            result = self.scan_json('incomplete', 2)
        self.assertIn('state_read', {f['check'] for f in result['findings']})
        self.assertNotIn('peer_change', {f['category'] for f in result['findings']})
        self.assertEqual(json.loads((self.root / 'state.json').read_text())['tailscale_peers'],
                         ['100.90.12.2', '100.90.12.3', 'fd7a:115c:a1e0::2'])
