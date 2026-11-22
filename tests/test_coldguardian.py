import contextlib
import io
import json
import os
import http.server
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest.mock import patch

from coldguardian import baseline, cli as n, notify, report, scan
from test_model import completion, stub


def setUpModule():
    global test_environment
    test_environment = patch.dict(os.environ)
    test_environment.start()
    os.environ.pop(notify.TOPIC_ENV, None)


def tearDownModule():
    test_environment.stop()


def settings(directory='/tmp/coldguardian-test'):
    return n.config({'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1', 'dns-a': '10.20.29.2'}, 'local_host': 'a-server', 'ports': '22,80', 'output_dir': directory})


def xml(hosts, ports=True):
    body = ''
    for ip, opened in hosts.items():
        body += '<host><status state="up"/><address addrtype="ipv4" addr="' + ip + '"/>'
        if ports:
            body += '<ports><extraports state="closed" count="' + str(2 - len(opened)) + '"/>'
            body += ''.join('<port protocol="tcp" portid="' + str(p) + '"><state state="open"/></port>' for p in opened) + '</ports>'
        body += '</host>'
    return '<nmaprun>' + body + '<runstats><finished exit="success"/></runstats></nmaprun>'


class ScopeTests(unittest.TestCase):
    def test_config_rejects_scope_and_options(self):
        base = {'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1'}}
        for override in ({'lan_cidr': '198.51.100.0/24'}, {'hosts': {'bad name': '10.20.29.1'}}, {'hosts': {'a-server': '10.20.29.0/24'}}, {'hosts': {'a-server': '198.51.100.4'}}, {'hosts': {'a-server': '::1'}}, {'ports': '22 --script=all'}, {'ports': '0'}, {'ports': '65536'}, {'ports': '80-22'}):
            with self.subTest(override=override), self.assertRaises((ValueError, TypeError)):
                n.config(dict(base, **override))

    def test_xml_diff_and_closed_only_host(self):
        current = scan.parse_nmap(xml({'10.20.30.2': [], '10.20.29.1': [22, 80]}), {'10.20.30.2', '10.20.29.1'}, 2, {22, 80})
        self.assertEqual(current, {'10.20.30.2': [], '10.20.29.1': [22, 80]})
        self.assertEqual(baseline.differences(current, {'10.20.29.1': [22]}), [{'category': 'new_ports', 'ip': '10.20.29.1', 'ports': [80]}, {'category': 'new_device', 'ip': '10.20.30.2'}])
        for document, allowed in ((xml({'198.51.100.4': []}), {'10.20.29.1'}), (xml({}), {'10.20.29.1'}), (xml({'10.20.29.1': [22]}).replace('count="1"', 'count="0"'), {'10.20.29.1'})):
            with self.assertRaises(ValueError):
                scan.parse_nmap(document, allowed, 2)

    def test_discovery_excludes_offline_inventory_and_scan_is_bounded(self):
        calls = []
        def fake(args, timeout, input=None):
            calls.append((args, timeout))
            if args[1] == '-sn':
                return xml({'10.20.30.2': []} if args[-1] == '10.20.30.0/24' else {'10.20.29.1': []}, False)
            return xml({'10.20.30.2': [], '10.20.29.1': [22]})
        with patch.object(scan, 'command', fake):
            snapshot, failures = scan.scan(settings())
        self.assertEqual(snapshot, {'10.20.30.2': [], '10.20.29.1': [22]})
        self.assertEqual(failures, [{'category': 'coverage', 'component': 'host_offline', 'host': 'dns-a', 'ip': '10.20.29.2', 'optional': False}, {'category': 'service', 'ip': '10.20.29.1', 'port': 22}])
        args, timeout = calls[-1]
        self.assertNotIn('10.20.29.2', args)
        self.assertNotIn('--open', args)
        self.assertEqual(args[args.index('--max-rate') + 1], '5000')
        self.assertEqual(timeout, 3600)


class LogTests(unittest.TestCase):
    def local_auth(self, path, outdir):
        return n.config({'lan_cidr': '10.20.30.0/24', 'hosts': {'a-server': '10.20.29.1'}, 'local_host': 'a-server', 'auth_paths': [str(path)], 'ports': '22,80', 'output_dir': str(outdir), 'suspicious_domains': ['evil.example']})

    def checkpoint(self, path):
        st = path.stat()
        return {'identity': str(st.st_dev) + ':' + str(st.st_ino), 'offset': 0}

    def test_collect_catches_up_multiple_chunks_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            row = 'Failed password for secret.evil.example from 10.20.30.20 token=TOPSECRET\n'
            path.write_text((row + row.replace('10.20.30.20', '10.20.30.21')) * 15000)
            c = self.local_auth(path, Path(temp) / 'reports')
            key = 'a-server:auth:' + str(path)
            read_chunk = n.read_log_chunk

            def read(log, start, discard_partial):
                data, end = read_chunk(log, start, discard_partial)
                self.assertLessEqual(end - start, 1024 * 1024)
                return data, end

            with patch.object(n, 'read_log_chunk', side_effect=read) as reader:
                pending, findings = n.collect(c, {key: self.checkpoint(path)})
            self.assertGreater(reader.call_count, 1)
            self.assertEqual(pending[key]['offset'], path.stat().st_size)
            self.assertEqual([f for f in findings if f['category'] == 'auth_failed'], [dict(category='auth_failed', count=15000, client_ip=ip, host='a-server', kind='auth') for ip in ('10.20.30.20', '10.20.30.21')])
            self.assertFalse(any(f['category'] == 'coverage' for f in findings))
            again, repeated = n.collect(c, pending)
            self.assertEqual(again, pending)
            self.assertFalse(any(f['category'] == 'auth_failed' for f in repeated))
            root = Path(c['output_dir'])
            root.mkdir(mode=0o700)
            with contextlib.redirect_stdout(io.StringIO()):
                report.report(root, findings)
            for stored in root.iterdir():
                for secret in ('TOPSECRET', 'secret.evil.example'):
                    self.assertNotIn(secret, stored.read_text())

    def test_collect_stops_at_chunk_budget_and_resumes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            row = 'Failed password for secret.evil.example from 10.20.30.20\n'
            path.write_text(row * 50000)
            key = 'a-server:auth:' + str(path)
            c = self.local_auth(path, temp)
            with patch.object(n, 'MAX_CHUNKS', 2):
                pending, findings = n.collect(c, {key: self.checkpoint(path)})
            self.assertGreater(pending[key]['offset'], n.READ_LIMIT)
            self.assertLessEqual(pending[key]['offset'], n.READ_LIMIT * 2)
            self.assertLess(pending[key]['offset'], path.stat().st_size)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='auth'), findings)
            self.assertIn(dict(category='source_summary', host='a-server', kind='auth', status='partial'), findings)
            end, rest = n.collect(c, pending)
            self.assertEqual(end[key]['offset'], path.stat().st_size)
            self.assertEqual(sum(f['count'] for f in findings + rest if f['category'] == 'auth_failed'), 50000)

    def test_collect_no_progress_and_deadline_are_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            path.write_bytes(b'x' * (n.READ_LIMIT + 1))
            key = 'a-server:auth:' + str(path)
            original = {key: self.checkpoint(path)}
            c = self.local_auth(path, temp)
            with patch.object(n, 'read_log_chunk', wraps=n.read_log_chunk) as reader:
                pending, findings = n.collect(c, original)
            self.assertEqual(reader.call_count, 1)
            self.assertEqual(pending, original)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='auth'), findings)
            with patch.object(n.time, 'monotonic', side_effect=[0, 61]), patch.object(n, 'open_log') as reader:
                pending, findings = n.collect(c, original)
            reader.assert_not_called()
            self.assertEqual(pending, original)
            self.assertIn(dict(category='source_summary', host='a-server', kind='auth', status='partial'), findings)

    def test_collect_later_read_error_preserves_source_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            path.write_text('Failed password from 192.0.2.10\n' * 2)
            key = 'a-server:auth:' + str(path)
            original = {key: self.checkpoint(path)}
            c = self.local_auth(path, temp)
            with patch.object(n, 'read_log_chunk', side_effect=[
                ('Failed password from 192.0.2.10\n', 32),
                OSError('TOPSECRET'),
            ]):
                pending, findings = n.collect(c, original)
            self.assertEqual(pending, original)
            self.assertIn(dict(category='coverage', component='log_read', host='a-server', kind='auth'), findings)
            self.assertFalse(any(f['category'] == 'auth_failed' for f in findings))

    def test_collect_deadline_after_progress_preserves_partial_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            data = 'Failed password from 192.0.2.10\n'
            path.write_text(data * 2)
            key = 'a-server:auth:' + str(path)
            original = {key: self.checkpoint(path)}
            c = self.local_auth(path, temp)
            with (patch.object(n.time, 'monotonic', side_effect=[0, 0, 59, 61]),
                  patch.object(n, 'READ_LIMIT', len(data))):
                pending, findings = n.collect(c, original)
            self.assertEqual(pending[key], dict(original[key], offset=len(data)))
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='auth'), findings)

    def test_collect_rejects_bad_cursor_without_losing_other_local_source(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            path.write_text('Failed password from 192.0.2.10\n')
            dns = Path(temp) / 'dns'
            dns.write_text('Jan 1 query[A] evil.example from 192.0.2.10\n')
            c = self.local_auth(path, temp)
            c['dns_paths'] = [str(dns)]
            key = 'a-server:auth:' + str(path)
            for bad in ({'identity': '1:2', 'offset': -1}, {'identity': [], 'offset': 0},
                        {'identity': '1:2'}, {'identity': '1:2', 'offset': True}):
                original = {key: bad}
                with self.subTest(checkpoint=bad):
                    pending, findings = n.collect(c, original)
                    self.assertEqual(pending, original)
                    self.assertIn(dict(category='coverage', component='log_read', host='a-server', kind='auth'), findings)
                    self.assertIn(dict(category='dns_suffix', count=1, client_ip='192.0.2.10', host='a-server', kind='dns'), findings)

    def test_dns_and_auth_are_redacted(self):
        data = json.dumps({'T': 'private timestamp', 'QH': 'secret.evil.example', 'IP': '10.20.30.20', 'Result': {'token': 'TOPSECRET'}})
        data += '\n' + json.dumps({'QH': 'a' * 45 + '.private.example', 'IP': '10.20.30.20'})
        data += '\nJan 1 query[A] child.evil.example from 10.20.30.20'
        findings = n.summarize_logs(data, 'dns', ['evil.example'])
        self.assertEqual(findings, [{'category': 'dns_long_label', 'count': 1, 'client_ip': '10.20.30.20'}, {'category': 'dns_suffix', 'count': 2, 'client_ip': '10.20.30.20'}])
        auth = n.summarize_logs('Failed password for private-user from 198.51.100.8 port 22\nauthentication failure; user=secret rhost=192.0.2.1\nFailed password for token-user', 'auth', [])
        self.assertEqual(sum(f['count'] for f in auth), 3)
        persisted = json.dumps(findings + auth)
        for secret in ('TOPSECRET', 'secret', 'example', 'private-user', 'token-user'):
            self.assertNotIn(secret, persisted)
        self.assertIsNone(n.dns_category('notevil.example', ['evil.example']))

    def test_local_auth_offsets_rotation_partial_and_initial_tail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            row = 'Failed password from 192.0.2.10'
            path.write_text(row + '\n' + row)
            key = 'a-server:auth:' + str(path)
            c = self.local_auth(path, temp)
            first, findings = n.collect(c, {})
            self.assertEqual(first[key]['offset'], len(row) + 1)
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)
            with path.open('a') as out:
                out.write('\n')
            second, findings = n.collect(c, first)
            self.assertEqual(second[key]['offset'], path.stat().st_size)
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)
            path.rename(Path(temp) / 'rotated')
            path.write_text(row + '\n')
            rotation, findings = n.collect(c, second)
            self.assertNotEqual(rotation[key]['identity'], second[key]['identity'])
            self.assertIn(dict(category='coverage', component='log_rotated', host='a-server', kind='auth'), findings)
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)
            path.write_text('ancient\n' * 50 + row + '\n')
            with patch.object(n, 'READ_LIMIT', len(row) + 4):
                tail, findings = n.collect(c, {})
            self.assertEqual(tail[key]['offset'], path.stat().st_size)
            self.assertIn(dict(category='coverage', component='log_history_skipped', host='a-server', kind='auth'), findings)
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)

    def test_collect_reads_local_auth_and_dns_without_subprocesses(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'auth'
            path.write_text('Failed password from 192.0.2.10\n')
            dns = Path(temp) / 'dns'
            dns.write_text('Jan 1 query[A] evil.example from 192.0.2.10\n')
            c = self.local_auth(path, temp)
            c['dns_paths'] = [str(dns)]
            legacy = {
                'old-host:dns:' + str(dns): self.checkpoint(dns),
                'old-host:auth:' + str(path): self.checkpoint(path),
            }
            with patch('subprocess.Popen', side_effect=AssertionError('log reader spawned a subprocess')):
                checkpoints, findings = n.collect(c, legacy)
            self.assertEqual(list(checkpoints), ['a-server:auth:' + str(path)])
            self.assertIn(dict(category='auth_failed', count=1, client_ip='192.0.2.10', host='a-server', kind='auth'), findings)
            self.assertIn(dict(category='dns_suffix', count=1, client_ip='192.0.2.10', host='a-server', kind='dns'), findings)
            self.assertIn(dict(category='source_summary', host='a-server', kind='dns', status='ok'), findings)

    def test_local_dns_reads_only_recent_complete_lines(self):
        with tempfile.TemporaryDirectory() as temp:
            dns = Path(temp) / 'dns'
            row = 'Jan 1 query[A] evil.example from 192.0.2.10\n'
            dns.write_text(row * 10 + row.rstrip())
            c = self.local_auth(dns, temp)
            c.update(auth_paths=[], dns_paths=[str(dns)])
            with patch.object(n, 'READ_LIMIT', 2 * len(row)):
                checkpoints, findings = n.collect(c, {})
            self.assertEqual(checkpoints, {})
            self.assertIn(dict(category='dns_suffix', count=1, client_ip='192.0.2.10', host='a-server', kind='dns'), findings)
            self.assertIn(dict(category='coverage', component='log_history_skipped', host='a-server', kind='dns'), findings)
            self.assertIn(dict(category='coverage', component='log_backlog', host='a-server', kind='dns'), findings)


class PersistenceTests(unittest.TestCase):
    def run_quietly(self, c, approve=False):
        with contextlib.redirect_stdout(io.StringIO()):
            return n.run(c, approve)

    def test_missing_baseline_explicit_approval_and_no_auto_promotion(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            hosts = {'10.20.30.2': [22], '10.20.29.1': [22]}
            offline = [n.finding('coverage', component='host_offline', host='dns-a', ip='10.20.29.2')]
            with patch.object(n, 'scan', return_value=(hosts, offline)), patch.object(n, 'collect', return_value=({}, [])):
                self.assertEqual(self.run_quietly(c), 1)
            root = Path(temp)
            self.assertFalse((root / 'baseline.json').exists())
            alert = json.loads((root / 'alerts.jsonl').read_text())
            self.assertIn({'category': 'baseline_missing'}, alert['findings'])
            self.assertIn({'category': 'observed_host', 'ip': '10.20.30.2', 'ports': [22]}, alert['findings'])
            self.assertEqual(alert['model_explanations'], {})
            self.assertEqual(self.run_quietly(c, True), 0)
            baseline = json.loads((root / 'baseline.json').read_text())
            self.assertEqual(baseline['hosts'], hosts)
            self.assertEqual(baseline['offline_inventory'], ['10.20.29.2'])
            state = json.loads((root / 'state.json').read_text())
            state['snapshot']['complete'] = False
            report.atomic_json(root / 'state.json', state)
            self.assertEqual(self.run_quietly(c, True), 2)
            self.assertEqual(json.loads((root / 'baseline.json').read_text()), baseline)
            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            state['snapshot']['complete'] = True
            state['snapshot']['fingerprint'] = 'mismatch'
            report.atomic_json(root / 'state.json', state)
            self.assertEqual(self.run_quietly(c, True), 2)

    def test_discovery_timeout_persists_coverage_and_refuses_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            with patch.object(scan, 'command', side_effect=subprocess.TimeoutExpired('SECRET_COMMAND', 90)), patch.object(n, 'collect', return_value=({}, [])):
                self.assertEqual(self.run_quietly(c), 1)
            alert_text = (Path(temp) / 'alerts.jsonl').read_text()
            self.assertNotIn('SECRET_COMMAND', alert_text)
            self.assertIn({'category': 'coverage', 'component': 'lan_discovery', 'error_type': 'TimeoutExpired'}, json.loads(alert_text)['findings'])
            self.assertEqual(self.run_quietly(c, True), 2)
            self.assertFalse((Path(temp) / 'baseline.json').exists())

    def test_report_failure_does_not_commit_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'offset': 100}, [])), patch.object(n, 'report', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    self.run_quietly(c)
            self.assertFalse((Path(temp) / 'state.json').exists())

    def test_model_skips_summaries_and_filters_prompt(self):
        summaries = [n.finding('source_summary', host='dns-a', kind='dns', status='ok'), n.finding('scan_summary', host_count=35)]
        findings = summaries + [n.finding('dns_long_label', host='dns-a', count=4, domain='SECRET.private.example', raw='TOPSECRET')]
        explanation = {'label': 'benign', 'reason': 'Check the device.', 'missing': [], 'evidence_ids': ['E3']}
        with stub(completion(json.dumps(explanation))) as (url, requests):
            for index, summary in enumerate(summaries, 1):
                self.assertIsNone(n.explain_finding(url, f"E{index}", summary))
            self.assertEqual(requests, [])
            self.assertEqual(n.explain_finding(url, 'E3', findings[2]), explanation)
        [(path, payload)] = requests
        self.assertEqual(path, '/v1/chat/completions')
        self.assertEqual(json.loads(payload['messages'][1]['content']), {
            'untrusted_evidence': {'E3': {'category': 'dns_long_label', 'host': 'dns-a', 'count': 4}},
        })
        serialized = json.dumps(payload)
        self.assertNotIn('SECRET.private.example', serialized)
        self.assertNotIn('TOPSECRET', serialized)

    def test_human_report_heading_coverage_and_private_atomic_latest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            telemetry = [n.finding('dns_long_label', count=9, client_ip='10.20.30.20', host='dns-a', kind='dns')]
            original_replace = os.replace
            replacements = []
            def replace(source, target):
                self.assertEqual(Path(source).stat().st_mode & 0o777, 0o600)
                replacements.append(target)
                return original_replace(source, target)
            with contextlib.redirect_stdout(io.StringIO()), patch.object(n.os, 'replace', replace):
                report.report(root, telemetry)
            latest = root / 'latest.md'
            first = latest.read_text()
            self.assertTrue(first.startswith('# No new security findings\n'))
            self.assertIn('Low-confidence indicator', first)
            self.assertIn('## Informational DNS patterns', first)
            self.assertNotIn('Next step:', first)
            self.assertNotIn('Suggested review:', first)
            self.assertIn('10.20.30.20: 9', first)
            self.assertIn('## Coverage', first)
            self.assertEqual(replacements, [latest])
            self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir()))
            with contextlib.redirect_stdout(io.StringIO()):
                report.report(root, telemetry, {'E1': {
                    'label': 'risk', 'reason': 'Review this DNS pattern.', 'evidence_ids': ['E1'], 'missing': [],
                }})
                self.assertRegex(latest.read_text(), r'E1\. Long DNS label events.*Model label: risk')
                self.assertTrue(latest.read_text().startswith('# No new security findings\n'))
                report.report(root, telemetry + [n.finding('new_ports', ip='10.20.30.20', ports=[80])])
                self.assertTrue(latest.read_text().startswith('# Attention needed\n'))
                self.assertIn('New open TCP ports at 10.20.30.20: 80', latest.read_text())
                report.report(root, [n.finding('coverage', component='log_backlog', host='dns-a', kind='dns')])
                self.assertTrue(latest.read_text().startswith('# Attention needed\n'))
                self.assertIn('Some log data remains unread', latest.read_text())
            self.assertEqual(json.loads((root / 'alerts.jsonl').read_text().splitlines()[0])['findings'], telemetry)
            self.assertEqual(len(list(root.glob('*.md'))), 5)
            self.assertTrue(any(p.read_text() == first for p in root.glob('*.md')))
            self.assertFalse(list(root.glob('.coldguardian-*')))

    def test_report_attention_rules_do_not_hide_deterministic_findings(self):
        cases = [(n.finding(category, count=2), False) for category in ('dns_long_label', 'dns_entropy')]
        cases += [(n.finding(category), True) for category in ('dns_suffix', 'auth_failed', 'new_device', 'new_ports', 'baseline_missing', 'baseline_mismatch', 'baseline_scope_review', 'coverage')]
        cases += [(n.finding('baseline_enrolled', approved_hosts='TOPSECRET'), False)]
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            for item, attention in cases:
                with self.subTest(category=item['category']):
                    report.report(root, [item])
                    text = (root / 'latest.md').read_text()
                    self.assertEqual(text.splitlines()[0], '# Attention needed' if attention else '# No new security findings')
                    self.assertNotIn('TOPSECRET', text)

    def test_report_unknown_fields_never_appear_in_markdown(self):
        with tempfile.TemporaryDirectory() as temp, contextlib.redirect_stdout(io.StringIO()):
            root = Path(temp)
            findings = [n.finding('baseline_enrolled', approved_hosts=35, raw='TOPSECRET'), n.finding('baseline_scope_review', detail='private.example'), n.finding('SECRET_CATEGORY', ip='private.example', count='TOPSECRET'), n.finding('coverage', component='SECRET_COMPONENT'), n.finding(['SECRET_CATEGORY'], host=['TOPSECRET'], component={'secret': 'private.example'})]
            report.report(root, findings, {'E4': {'label': 'risk', 'reason': 'Review.', 'evidence_ids': ['E4'],
                                                 'missing': [], 'raw': 'MODELSECRET'}})
            text = (root / 'latest.md').read_text()
            self.assertIn('Initial network reference saved. Future changes remain monitored. Approved hosts: 35.', text)
            self.assertIn('network reference needs scope review', text)
            for raw in ('TOPSECRET', 'private.example', 'SECRET_CATEGORY', 'SECRET_COMPONENT', 'MODELSECRET', '"category"'):
                self.assertNotIn(raw, text)

    def test_latest_failure_does_not_commit_checkpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            c = settings(temp)
            root = Path(temp)
            state = {'checkpoints': {'saved-source': {'identity': '1:2', 'offset': 50}}}
            report.atomic_json(root / 'state.json', state)
            report.atomic_text(root / 'latest.md', 'previous complete report\n')
            original = os.replace
            def replace(source, target):
                if target == root / 'latest.md':
                    raise OSError('disk full')
                return original(source, target)
            with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'offset': 100}, [])), patch.object(n.os, 'replace', replace):
                with self.assertRaises(OSError):
                    self.run_quietly(c)
            self.assertEqual(json.loads((root / 'state.json').read_text()), state)
            self.assertEqual((root / 'latest.md').read_text(), 'previous complete report\n')
            self.assertFalse(list(root.glob('.coldguardian-*')))


class NotificationTests(unittest.TestCase):
    topic = 'test-topic-never-production'

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.topic_file = self.root / 'topic'
        self.topic_file.write_text(self.topic + '\n')
        self.environment = patch.dict(os.environ, {notify.TOPIC_ENV: str(self.topic_file)})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        digest_off = patch.object(notify, 'DIGEST_HOUR', 25)
        digest_off.start()
        self.addCleanup(digest_off.stop)

    @contextlib.contextmanager
    def server(self, status=200, body=None):
        calls = []
        payload = body if body is not None else json.dumps({'id': 'AbCdEf123456', 'topic': self.topic}).encode()
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append((self.path, dict(self.headers), self.rfile.read(int(self.headers['Content-Length']))))
                self.send_response(status)
                if status == 302:
                    self.send_header('Location', '/sink')
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass
        server = http.server.ThreadingHTTPServer(('localhost', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        original = notify.urllib.request.OpenerDirector.open
        def loopback(opener, request, timeout):
            self.assertEqual(request.full_url, 'https://ntfy.sh/' + self.topic)
            self.assertEqual(timeout, 8)
            local = notify.urllib.request.Request(f'http://{server.server_address[0]}:{server.server_port}/publish',
                                                 data=request.data, headers=dict(request.header_items()), method='POST')
            return original(opener, local, timeout=timeout)
        try:
            with patch.object(notify.urllib.request.OpenerDirector, 'open', loopback):
                yield calls
        finally:
            server.shutdown()
            server.server_close()
            worker.join()

    def test_notification_items_keep_sanitized_text_counts_and_page_events(self):
        categories = {
            'new_device': ('new_device:10.20.30.9', 'New device at 10.20.30.9'),
            'baseline_missing': ('baseline_missing', notify.PAGE_NOTES['baseline_missing']),
        }
        for category, (key, text) in categories.items():
            with self.subTest(category=category):
                self.assertEqual(notify.notification_items([n.finding(category, ip='10.20.30.9')]), {key: {'text': text, 'count': 1, 'page_events': {category}}})
        ports = notify.notification_items([n.finding('new_ports', ip='10.20.30.9', ports=[22, 80])])
        self.assertEqual(ports, {'new_ports:10.20.30.9:22, 80': {'text': 'New open ports on 10.20.30.9: 22, 80', 'count': 1, 'page_events': {'new_ports'}}})
        digest = [n.finding('auth_failed', count=3, host='a-server', client_ip='10.20.30.9'), n.finding('dns_entropy', count=8, host='dns-a'),
                  n.finding('dns_long_label', count=2, host='dns-a'), n.finding('dns_suffix', count=1, host='dns-a'), n.finding('coverage', component='tcp_scan')]
        digest += [n.finding('coverage', component='host_offline', host=host) for host in ('a-server', 'dns-a')]
        for key, found in notify.notification_items(digest).items():
            self.assertEqual(found['page_events'], {'coverage'} if key.startswith('coverage_') else set())
        self.assertEqual(len(notify.notification_items(digest)), 5 + 2)
        self.assertEqual(notify.notification_items([n.finding('auth_failed', count=3, host='a-server', client_ip='10.20.30.9')]),
                         {'auth_failed on a-server from 10.20.30.9': {'text': 'Failed sign-ins on a-server from 10.20.30.9', 'count': 3, 'page_events': set()}})
        routine = [n.finding(category) for category in ('baseline_approved', 'baseline_enrolled', 'observed_host', 'source_summary', 'scan_summary', 'unknown')]
        routine += [n.finding('coverage', component=c) for c in ('log_rotated', 'log_history_skipped', 'notification_delivery')]
        routine.append(n.finding('coverage', component='host_offline', host='laptop-a', optional=True))
        self.assertEqual(notify.notification_items(routine), {})

    def test_each_item_pages_once_even_as_devices_come_and_go(self):
        state = {}
        a, b = n.finding('new_device', ip='10.20.30.9'), n.finding('new_device', ip='10.20.30.10')
        def deliver(findings, now):
            return notify.deliver_notification(state, findings, lambda: None, now=now)['status']
        with patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            self.assertEqual(deliver([a], 100), 'accepted')
            self.assertEqual(deliver([a, b], 200), 'accepted')
            self.assertEqual(sender.call_args.args[0], ['New device at 10.20.30.10'])
            self.assertEqual(deliver([b], 300), 'unchanged')
            self.assertEqual(deliver([a], 400), 'unchanged')
            self.assertEqual(deliver([], 500), 'quiet')
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(deliver([a], 100 + notify.PAGED_TTL + 1), 'accepted')

    def test_digest_sends_once_after_the_morning_hour_and_lists_unreviewed_items(self):
        state = {}
        day = time.mktime((2026, 10, 24, 0, 0, 0, 0, 0, -1))
        findings = [n.finding('new_device', ip='10.20.30.9'), n.finding('dns_entropy', count=8, host='dns-a')]
        with patch.object(notify, 'DIGEST_HOUR', 8), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            notify.deliver_notification(state, findings, lambda: None, now=int(day + 3 * 3600))
            self.assertEqual([c.kwargs.get('mode', 'alert') for c in sender.call_args_list], ['alert'])
            notify.deliver_notification(state, findings, lambda: None, now=int(day + 8 * 3600))
            self.assertEqual([c.kwargs.get('mode', 'alert') for c in sender.call_args_list], ['alert', 'digest'])
            self.assertEqual(sender.call_args.args[0], ['High-entropy DNS labels on dns-a (x16)', 'New device at 10.20.30.9 (x2)'])
            notify.deliver_notification(state, findings, lambda: None, now=int(day + 9 * 3600))
            notify.deliver_notification(state, [], lambda: None, now=int(day + 20 * 3600))
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(state['notification']['digest'], {'new_device:10.20.30.9': {'text': 'New device at 10.20.30.9', 'count': 1}, 'dns_entropy on dns-a': {'text': 'High-entropy DNS labels on dns-a', 'count': 8}})
            notify.deliver_notification(state, [], lambda: None, now=int(day + 86400 + 9 * 3600))
            self.assertEqual(sender.call_count, 3)
            self.assertEqual(sender.call_args.args[0], ['High-entropy DNS labels on dns-a (x8)', 'New device at 10.20.30.9'])

    def test_quiet_day_still_sends_a_heartbeat_digest_and_failure_retries(self):
        state = {}
        now = int(time.mktime((2026, 10, 24, 9, 0, 0, 0, 0, -1)))
        failure = {'status': 'failed', 'error_type': 'TransportError'}
        with patch.object(notify, 'DIGEST_HOUR', 8), patch.object(notify, 'send', side_effect=[failure, {'status': 'accepted'}]) as sender:
            self.assertEqual(notify.deliver_notification(state, [], lambda: None, now=now), failure)
            self.assertEqual(notify.deliver_notification(state, [], lambda: None, now=now + 1800)['status'], 'accepted')
            self.assertEqual(notify.deliver_notification(state, [], lambda: None, now=now + 3600)['status'], 'quiet')
        self.assertEqual(sender.call_count, 2)
        self.assertEqual(sender.call_args.kwargs, {'mode': 'digest'})

    def test_disabled_never_reads_a_topic_or_changes_baseline_fingerprint(self):
        before = settings()['_fingerprint']
        self.assertEqual(settings()['_fingerprint'], before)
        os.environ.pop(notify.TOPIC_ENV)
        with patch('builtins.open', side_effect=AssertionError('disabled must not read files')):
            self.assertEqual(notify.send(mode='test'), {'status': 'disabled'})
            self.assertEqual(notify.deliver_notification({}, [n.finding('new_ports')], {}, lambda: None), {'status': 'disabled'})
        self.assertEqual(settings()['_fingerprint'], before)

    def test_sender_payload_priorities_and_private_receipt(self):
        lines = ['New device at 10.20.30.9', 'New open ports on 10.20.30.9: 22'] + ['x'] * 8
        with self.server() as calls, patch.dict(os.environ, {'http_proxy': 'http://localhost:1', 'https_proxy': 'http://localhost:1', 'no_proxy': ''}):
            result = notify.send(lines, delayed=True)
            self.assertEqual(result, {'status': 'accepted', 'id': 'AbCdEf123456'})
            self.assertEqual(notify.send(mode='test'), result)
            self.assertEqual(notify.send(mode='failure'), result)
            self.assertEqual(notify.send([], mode='digest'), result)
            self.assertEqual(notify.send(['\N{SNOWMAN}'], mode='digest'), result)
        path, headers, body = calls[0]
        self.assertEqual(path, '/publish')
        self.assertEqual(headers['Priority'], '4')
        self.assertTrue(headers['Title'].isascii())
        self.assertEqual(body.decode().splitlines(), ['Delayed from an earlier delivery failure.', *lines[:8], '+2 more in the local report.', 'Alert only; nothing was changed.'])
        self.assertEqual(calls[1][1]['Priority'], '3')
        self.assertEqual(calls[1][2], b'Coldguardian test notification. Alert-only monitoring.')
        self.assertEqual(calls[2][1]['Priority'], '4')
        self.assertIn(b'scanner failed to complete; monitoring incomplete', calls[2][2])
        self.assertEqual(calls[3][2], b'Nothing new since the last digest.')
        self.assertEqual(calls[3][1]['Title'], 'Coldguardian morning digest')
        self.assertEqual(calls[4][2], b'?')
        self.assertNotIn(self.topic, body.decode() + json.dumps(result))

    def test_actual_redirect_rejected_and_errors_do_not_leak(self):
        with self.server(302, b'PRIVATE_RESPONSE') as calls:
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'HTTPError'})
        self.assertEqual(len(calls), 1)
        with self.server(503, b'PRIVATE_RESPONSE'):
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'HTTPError'})
        with patch.object(notify.urllib.request.OpenerDirector, 'open', side_effect=RuntimeError('PRIVATE_URL_TOPIC_RESPONSE')):
            self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'TransportError'})

    def test_topic_validation_and_response_bounds(self):
        for topic in ('', 'bad/topic', 'bad\r\nTitle: leak', 'x' * 65, 'https://private.example', '\N{SNOWMAN}'):
            self.topic_file.write_text(topic)
            with self.subTest(topic=topic), patch.object(notify.urllib.request.OpenerDirector, 'open') as sender:
                self.assertEqual(notify.send(mode='test'), {'status': 'failed', 'error_type': 'TopicFileError'})
                sender.assert_not_called()
        self.topic_file.unlink()
        self.assertEqual(notify.send(mode='failure'), {'status': 'failed', 'error_type': 'TopicFileError'})
        self.topic_file.write_text(self.topic)
        for body in (b'not json', json.dumps({'id': 'https://private.example', 'topic': self.topic}).encode(), b'x' * 9000):
            response = io.BytesIO(body)
            response.status = 200
            with patch.object(notify.urllib.request.OpenerDirector, 'open', return_value=response):
                self.assertEqual(notify.send(mode='test'), {'status': 'accepted'})
        self.topic_file.write_text('AbCdEf123456')
        response = io.BytesIO(b'{"id":"AbCdEf123456"}')
        response.status = 200
        with patch.object(notify.urllib.request.OpenerDirector, 'open', return_value=response):
            self.assertEqual(notify.send(mode='test'), {'status': 'accepted'})

    def test_failed_page_is_retried_until_accepted_and_state_stays_bounded(self):
        state = {}
        failure = {'status': 'failed', 'error_type': 'HTTPError'}
        many = [n.finding('new_device', ip='192.168.%d.%d' % (i // 250, i % 250 + 1)) for i in range(400)]
        with patch.object(notify, 'send', return_value=failure) as sender:
            self.assertEqual(notify.deliver_notification(state, many, lambda: None, now=100), failure)
            self.assertEqual(notify.deliver_notification(state, [], lambda: None, now=200), failure)
            self.assertEqual(sender.call_count, 2)
            self.assertEqual(state['notification']['paged'], {})
        with patch.object(notify, 'send', return_value={'status': 'accepted'}):
            notify.deliver_notification(state, [], lambda: None, now=300)
        self.assertEqual(state['notification']['pending'], {})
        saved = {key: len(state['notification'][key]) for key in ('paged', 'digest')}
        self.assertEqual(saved, {'paged': notify.MAX_SAVED, 'digest': notify.MAX_SAVED})

    def test_failed_transient_pending_survives_clean_scan_without_double_logs(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        hosts = {'10.20.29.1': [22]}
        report.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': hosts})
        report.atomic_json(output / 'state.json', {'checkpoints': {'auth': 5}, 'snapshot': {'old': True}})
        def failed(lines, delayed=False):
            self.assertEqual(lines, ['New device at 10.20.30.9'])
            self.assertFalse(delayed)
            initial = list(output.glob('*.md'))
            self.assertEqual(len(initial), 1)
            self.assertIn('New device observed at 10.20.30.9', initial[0].read_text())
            self.assertFalse((output / 'alerts.jsonl').exists())
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['checkpoints'], {'auth': 5})
            self.assertEqual(saved['notification']['pending'], {'new_device:10.20.30.9': {
                'text': 'New device at 10.20.30.9', 'page_events': ['new_device']}})
            self.assertEqual(saved['notification']['paged'], {})
            return {'status': 'failed', 'error_type': 'TransportError'}
        with contextlib.redirect_stdout(io.StringIO()), patch.object(n, 'scan', return_value=(hosts, [])):
            with patch.object(n, 'collect', return_value=({'auth': 100}, [n.finding('new_device', ip='10.20.30.9')])), patch.object(notify, 'send', side_effect=failed):
                self.assertEqual(n.run(c), 1)
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['checkpoints'], {'auth': 100})
            self.assertEqual(list(saved['notification']['pending']), ['new_device:10.20.30.9'])
            self.assertEqual(saved['notification']['delivery']['status'], 'failed')
            rows = (output / 'alerts.jsonl').read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertIn(n.finding('coverage', component='notification_delivery'), json.loads(rows[0])['findings'])
            self.assertIn('Phone notification delivery failed', (output / 'latest.md').read_text())
            with patch.object(n, 'collect', return_value=({'auth': 100}, [])), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
                self.assertEqual(n.run(c), 0)
                sender.assert_called_once_with(['New device at 10.20.30.9'], delayed=True)
                self.assertEqual(n.run(c), 0)
                self.assertEqual(sender.call_count, 1)
            saved = json.loads((output / 'state.json').read_text())
            self.assertEqual(saved['notification']['pending'], {})
            self.assertEqual(len((output / 'alerts.jsonl').read_text().splitlines()), 3)
            self.assertNotIn(self.topic, ''.join(p.read_text() for p in output.iterdir()))

    def test_scan_new_port_calls_real_sender_despite_model_none(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        report.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': {'10.20.29.1': [22], '10.20.30.2': []}})
        def scan_command(args, timeout, input=None):
            if args[1] == '-sn':
                return xml({'10.20.30.2': []} if args[-1] == '10.20.30.0/24' else {'10.20.29.1': [], '10.20.29.2': []}, False)
            return xml({'10.20.29.1': [22, 80], '10.20.29.2': [], '10.20.30.2': []})
        with self.server() as calls, patch.object(scan, 'command', side_effect=scan_command), patch.object(n, 'collect', return_value=({}, [])), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.run(c), 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2].decode().splitlines(), ['New device at 10.20.29.2', 'New open ports on 10.20.29.1: 80', 'Alert only; nothing was changed.'])
        state = json.loads((output / 'state.json').read_text())
        self.assertEqual(state['notification']['delivery'], {'status': 'accepted', 'id': 'AbCdEf123456'})
        self.assertEqual(sorted(state['notification']['paged']), ['new_device:10.20.29.2', 'new_ports:10.20.29.1:80'])
        self.assertEqual(state['snapshot']['fingerprint'], c['_fingerprint'])
        self.assertIn('New open TCP ports at 10.20.29.1: 80', (output / 'latest.md').read_text())

    def test_routine_run_keeps_local_notes_without_phone_delivery(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        hosts = {'10.20.29.1': [22]}
        report.atomic_json(output / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': hosts})
        notes = [n.finding('coverage', component=component) for component in ('log_rotated', 'log_history_skipped')]
        notes.append(n.finding('dns_long_label', count=17))
        with patch.object(n, 'scan', return_value=(hosts, [n.finding('coverage', component='host_offline', host='laptop-a', optional=True)])), patch.object(n, 'collect', return_value=({}, notes)), patch.object(notify, 'send', side_effect=AssertionError('routine notes must stay local')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(n.run(c), 1)
        text = (output / 'latest.md').read_text()
        self.assertIn('Long DNS label events: 17', text)
        self.assertIn('A log rotated', text)
        self.assertIn('No phone notification was needed.', text)

    def test_report_failure_before_send_never_delivers_or_advances(self):
        with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'auth': 100}, [])), patch.object(report, 'private_file', side_effect=OSError('disk full')), patch.object(notify, 'send') as sender:
            with self.assertRaises(OSError):
                n.run(settings(str(self.root / 'reports')))
        sender.assert_not_called()
        self.assertFalse((self.root / 'reports' / 'state.json').exists())

    def test_final_report_failure_keeps_pending_and_old_checkpoints(self):
        output = self.root / 'reports'
        output.mkdir()
        c = settings(str(output))
        report.atomic_json(output / 'state.json', {'checkpoints': {'auth': 5}})
        original = os.replace
        def replace(source, target):
            if target == output / 'latest.md':
                raise OSError('disk full')
            return original(source, target)
        with patch.object(n, 'scan', return_value=({'10.20.29.1': [22]}, [])), patch.object(n, 'collect', return_value=({'auth': 100}, [n.finding('auth_failed', count=3)])), patch.object(n.os, 'replace', side_effect=replace), patch.object(notify, 'send', return_value={'status': 'accepted'}) as sender:
            with self.assertRaises(OSError):
                n.run(c)
        self.assertEqual(sender.call_count, 1)
        saved = json.loads((output / 'state.json').read_text())
        self.assertEqual(saved['checkpoints'], {'auth': 5})
        self.assertEqual(saved['notification']['paged'], {})
        self.assertEqual(saved['notification']['pending'], {'baseline_missing': {
            'text': notify.PAGE_NOTES['baseline_missing'], 'page_events': ['baseline_missing']}})
        self.assertEqual(saved['notification']['digest']['auth_failed']['count'], 3)
        self.assertEqual(len((output / 'alerts.jsonl').read_text().splitlines()), 1)

    def test_cli_notification_modes_do_not_read_config_or_scan(self):
        for flag in ('--test-notification', '--notify-failure'):
            with self.subTest(flag=flag), self.server() as calls, patch.object(n, 'config', side_effect=AssertionError('must not parse scan config')), patch.object(n, 'run', side_effect=AssertionError('must not scan')), contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(n.main([flag]), 0)
                self.assertEqual(n.main([flag, '--config', '/missing/private/config']), 0)
            self.assertEqual(len(calls), 2)
            self.assertEqual(stdout.getvalue(), 'Notification accepted. ID: AbCdEf123456\n' * 2)
        os.environ[notify.TOPIC_ENV] = '/missing/private/topic'
        for flag in ('--test-notification', '--notify-failure'):
            result = subprocess.run([sys.executable, '-m', 'coldguardian.cli', flag], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, 'Notification failed (TopicFileError).\n')
            self.assertEqual(result.stderr, '')
        result = subprocess.run([sys.executable, '-m', 'coldguardian.cli'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--config is required', result.stderr)


if __name__ == '__main__':
    unittest.main()
