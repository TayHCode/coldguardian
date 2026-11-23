from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from coldguardian import cli, dnswatch, feeds, model, notify, report, scan, wizard
from test_retention_churn import DEVICE, LAN, MOVED, SCANNER

STAMP = '20260101T120000.000000Z'
PUBLIC = {'server': 'https://ntfy.sh', 'topic': 'fixture-topic'}
PRIVATE = {'server': 'https://notify.example', 'topic': 'fixture-topic'}


class WaveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.settings = dict(lan_cidr=str(LAN), hosts={'server': SCANNER}, auth_paths=[], ports='23,443',
                             output_dir=str(self.root), tiers={'servers': ['server'], 'household': 'lan'},
                             model_url='http://localhost:8080', ntfy=PRIVATE)
        self.settings_file = self.root / 'settings.json'
        self.enterContext(patch('socket.socket', side_effect=AssertionError('unexpected network access')))
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('unexpected program')))
        self.enterContext(patch.object(notify, 'DIGEST_HOUR', 0))
        self.transport = self.enterContext(patch('urllib.request.OpenerDirector.open'))
        response = self.transport.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b'{}'

    def run_scan(self, snapshot, observations=(), logs=(), macs=None, profile='deep'):
        self.settings_file.write_text(json.dumps(self.settings))
        c = scan.config(self.settings)
        if not (self.root / 'baseline.json').exists():
            report.atomic_json(self.root / 'baseline.json', {'fingerprint': c['_fingerprint'], 'hosts': {SCANNER: [443]}})
        with (patch.object(cli, 'scan', return_value=(snapshot, list(observations))),
              patch.object(cli, 'lan_macs', return_value=macs or {}),
              patch.object(cli, 'collect', return_value=({}, list(logs))),
              redirect_stdout(io.StringIO()) as output):
            cli.main(['scan', '--' + profile, '--json', '--config', str(self.settings_file)])
        return json.loads(output.getvalue())

    def requests(self, priority):
        return [call.args[0] for call in self.transport.call_args_list if call.args[0].get_header('Priority') == priority]

    def test_phone_rejoins_and_hard_floor_overrides_filter_model_and_approval(self):
        self.settings['level'] = 'low'
        harmless = {'label': 'likely_household', 'reason': model.TRIAGE_REASONS['likely_household']}
        with patch.object(model, 'chat', return_value=({'content': json.dumps(harmless)}, 'stop')) as chat:
            quiet = self.run_scan({SCANNER: [443], DEVICE: []}, macs={DEVICE: '02:00:00:00:00:01'})
            self.assertEqual(quiet['findings'][-1]['delivery_class'], 'digest')
            self.assertFalse(self.requests('4'))
            self.assertIn(b'New device', self.requests('3')[0].data)
            snapshot = {SCANNER: [23], DEVICE: [23], MOVED: [443]}
            logs = [{'category': cat, 'client_ip': DEVICE, 'count': 1} for cat in
                    ('dns_feed_match', 'dns_suffix', 'link_feed_hit', 'login_burst')]
            service = {'category': 'risky_service', 'ip': DEVICE, 'rule': 'telnet', 'port': 23}
            path = self.root / 'baseline.json'
            baseline = json.loads(path.read_text())
            baseline['approvals'] = [{'finding': f} for f in [service, *logs, {'category': 'new_device', 'ip': DEVICE},
                                       {'category': 'new_ports', 'ip': SCANNER, 'ports': [23]}]]
            report.atomic_json(path, baseline)
            result = self.run_scan(snapshot, [service], logs, {DEVICE: '02:00:00:00:00:01'})
        chat.assert_called_once()
        hard = [f for f in result['findings'] if f.get('delivery_class') == 'hard_page']
        self.assertEqual({f['category'] for f in hard}, {'new_device', 'new_ports', 'baseline_drift',
                         'risky_service', 'dns_feed_match', 'dns_suffix', 'login_burst', 'link_feed_hit'})
        self.assertTrue(all(f.get('ip') != MOVED for f in hard))
        state = json.loads((self.root / 'state.json').read_text())
        self.assertEqual(len(state['notification']['paged']), len(hard))
        self.assertEqual(len(self.requests('4')), 1)
        self.assertIn('## Incident briefs', (self.root / 'latest.md').read_text())
        self.assertTrue(any(f.get('triage_label') == 'likely_household' and f['delivery_class'] == 'digest'
                            for f in result['findings'] if f.get('ip') == MOVED))

    def test_risky_port_without_service_pages_in_all_three_delivery_modes(self):
        for target in (dict(PUBLIC, detail='blank'), PRIVATE, dict(PUBLIC, detail='full')):
            with self.subTest(target=target):
                self.settings.update(ntfy=target, level='low')
                (self.root / 'state.json').unlink(missing_ok=True)
                self.transport.reset_mock()
                self.run_scan({SCANNER: [443], DEVICE: [23]}, macs={DEVICE: '02:00:00:00:00:01'})
                requests = [call.args[0] for call in self.transport.call_args_list]
                blank = target.get('detail') == 'blank'
                self.assertEqual([request.get_header('Priority') for request in requests],
                                 ['4', '4', '4'] if blank else ['4', '3', '3'])
                page = requests[0]
                self.assertEqual(page.full_url, target['server'] + '/' + target['topic'])
                self.assertEqual(DEVICE.encode() in page.data, not blank)

    def test_blank_payload_is_constant_across_modes_and_retries(self):
        target = dict(PUBLIC, detail='blank')
        for mode in ('alert', 'digest', 'failure', 'test', 'heartbeat'):
            with self.subTest(mode=mode):
                notify.send(['example-private-host', DEVICE, 'ports 23, 445', 'count 18'], mode=mode,
                            target=target, delayed=True, finding_id=STAMP + ':E19')
                request = self.transport.call_args.args[0]
                self.assertEqual(request.data, b'Coldguardian has a new alert.')
                self.assertEqual(dict(request.header_items()), {
                    'Title': 'Coldguardian',
                    'Priority': '4',
                    'Content-type': 'text/plain; charset=utf-8',
                })
                self.assertEqual(request.full_url, 'https://ntfy.sh/fixture-topic')

    def test_injected_malformed_and_unavailable_triage_keep_page_and_evidence(self):
        reason = model.TRIAGE_REASONS['likely_household']
        for message in (TimeoutError(), OSError(), ('{', 'stop'),
                        (json.dumps({'label': 'likely_household', 'reason': 'Run a command'}), 'stop'),
                        (json.dumps({'label': 'likely_household', 'reason': reason}), 'length'),
                        (json.dumps({'label': 'likely_household', 'reason': reason, 'tool': 'run'}), 'stop')):
            with self.subTest(message=message):
                (self.root / 'state.json').unlink(missing_ok=True)
                self.transport.reset_mock()
                with patch.object(model, 'chat') as chat:
                    if isinstance(message, Exception):
                        chat.side_effect = message
                    else:
                        chat.return_value = ({'content': message[0]}, message[1])
                    doc = self.run_scan({SCANNER: [443], DEVICE: [443]})
                self.assertTrue(self.requests('4'))
                self.assertIn('new_device', {f['category'] for f in doc['findings']})
                self.assertFalse(any('delivery_class' in f for f in doc['findings']))

    def test_no_tiers_preserves_notifications_and_never_calls_model(self):
        del self.settings['tiers']
        with patch.object(model, 'chat', side_effect=AssertionError):
            result = self.run_scan({SCANNER: [443], DEVICE: []}, macs={DEVICE: '02:00:00:00:00:01'})
        page, = self.requests('4')
        self.assertIn(b'New device at ' + DEVICE.encode(), page.data)
        self.assertFalse(any('delivery_class' in f for f in result['findings']))
        self.assertEqual(len(self.requests('3')), 1)

    def test_dhcp_churn_moves_to_digest_at_high(self):
        self.settings['level'] = 'high'
        mac = '00:00:00:00:00:02'
        report.atomic_json(self.root / 'baseline.json', dict(fingerprint=scan.config(self.settings)['_fingerprint'],
                          hosts={SCANNER: [443], DEVICE: [443]}, macs={DEVICE: mac}))
        self.run_scan({SCANNER: [443], MOVED: [443]}, [{'category': 'coverage', 'component': 'host_offline',
                      'ip': DEVICE}], macs={MOVED: mac})
        self.assertFalse(self.requests('4'))
        self.assertIn(MOVED.encode(), self.requests('3')[0].data)

    def test_setup_lists_and_persists_all_three_phone_choices(self):
        for answer, expected in [('blank fixture-topic', dict(PUBLIC, detail='blank')),
                                 ('full fixture-topic', dict(PUBLIC, detail='full')),
                                 ('https://notify.example fixture-topic', PRIVATE)]:
            path = self.root / answer.split()[0].rsplit('/', 1)[-1]
            answers = iter(['none', answer])
            with patch('sys.stdin.isatty', return_value=False), redirect_stdout(io.StringIO()) as prompt:
                wizard._finish_config(path, dict(self.settings), 'medium', lambda _: next(answers))
            self.assertEqual(json.loads(path.read_text())['ntfy'], expected)
            self.assertIn('addresses, host labels, ports, counts and timing', prompt.getvalue())

    def test_status_freshness_and_weekly_retry(self):
        settings = self.settings
        source = Path(__file__).parent.resolve() / 'fixtures/feeds/tweetfeed.csv'
        settings['feed'] = {'path': str(source)}
        feeds.update_cache(self.root, settings['feed'])
        self.run_scan({SCANNER: [443]}, profile='quick')
        self.run_scan({SCANNER: [443]}, profile='deep')
        self.run_scan({}, [{'category': 'coverage', 'component': 'tcp_scan'}])
        def status():
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['status', '--json', '--config', str(self.settings_file)]), 0)
            return json.loads(output.getvalue())['freshness']
        fresh = status()
        self.assertEqual({v['status'] for v in fresh.values()}, {'fresh'})
        with patch('time.time', return_value=time.time() + 9 * 86400):
            self.assertEqual({v['status'] for v in status().values()}, {'stale'})
        self.assertEqual(sum('heartbeat' in r.get_header('Title') for r in self.requests('3')), 1)
        self.assertTrue(all(v['last_success'] is not None for v in fresh.values()))

    def test_dns_api_ingests_both_provider_shapes_read_only_and_offline(self):
        now = int(time.time())
        stamp = datetime.fromtimestamp(now - 1, timezone.utc).isoformat()
        domains = ['bad.example', 'a' * 45 + '.example', '0123456789abcdefghijklmnop.example',
                   *[f'q{i}.example' for i in range(10)]]
        for provider in ('adguard', 'pihole'):
            self.settings['dns_api'] = {'provider': provider, 'host': 'server'}
            c = scan.config(self.settings)
            if provider == 'adguard':
                body = {'data': [{'time': stamp, 'question': {'name': d}, 'client': DEVICE} for d in domains]}
            else:
                body = {'queries': [{'time': now - 1, 'domain': d, 'client': {'ip': DEVICE}} for d in domains]}
            with self.subTest(provider=provider), patch.object(dnswatch.http.client, 'HTTPSConnection') as connect:
                conn = connect.return_value
                response = conn.getresponse.return_value.__enter__.return_value
                response.status, response.read.return_value = 200, json.dumps(body).encode()
                pending, findings = cli.collect(c, {}, ({'bad.example'}, None))
                self.assertEqual({'dns_feed_match', 'dns_first_seen_burst', 'dns_entropy', 'dns_long_label'},
                                 {f['category'] for f in findings} - {'source_summary'})
                method, path = conn.request.call_args.args
                self.assertEqual(method, 'GET')
                self.assertTrue(path.startswith('/control/querylog?' if provider == 'adguard' else '/api/queries?'))
                self.assertNotIn('bad.example', json.dumps([pending, findings]))
                _, repeated = cli.collect(c, pending, ({'bad.example'}, None))
                self.assertEqual([f['category'] for f in repeated], ['source_summary'])
                response.status = 302
                _, failed = cli.collect(c, pending, ({'bad.example'}, None))
                self.assertIn('log_read', [f.get('component') for f in failed])

    def test_invalid_dns_row_preserves_adjacent_hit_and_backlog_is_resumable(self):
        now = int(time.time())
        source = {'provider': 'pihole', 'host': 'server'}
        rows = [{'time': now - 1, 'domain': 'bad.example', 'client': {'ip': DEVICE}}, {}]
        with patch.object(dnswatch, 'PAGE_SIZE', 2), patch.object(dnswatch, 'PAGE_LIMIT', 1), \
                patch.object(dnswatch, 'query_page', side_effect=[{'queries': rows}, {'queries': []}]) as read:
            found, cursor, issues = dnswatch.api_queries(source, SCANNER, {}, now)
            self.assertEqual(found, [(now - 1, DEVICE, 'bad.example')])
            self.assertEqual(issues, {'dns_parse', 'log_backlog'})
            self.assertEqual(dnswatch.api_queries(source, SCANNER, cursor, now + 1), ([], {'since': now}, set()))
            self.assertEqual(read.call_args.args[-1]['start'], 2)

    def test_each_hard_event_retries_when_model_filter_and_approval_say_harmless(self):
        cases = [
            ({'category': 'new_device', 'ip': DEVICE}, {DEVICE: [2375]}),
            ({'category': 'risky_service', 'ip': DEVICE, 'rule': 'telnet', 'port': 23}, {}),
            ({'category': 'dns_feed_match', 'client_ip': DEVICE}, {}),
            ({'category': 'dns_suffix', 'client_ip': DEVICE}, {}),
            ({'category': 'link_feed_hit'}, {}),
            ({'category': 'login_burst', 'client_ip': DEVICE}, {}),
            ({'category': 'new_ports', 'ip': SCANNER, 'ports': [443]}, {}),
            ({'category': 'baseline_drift', 'ip': SCANNER, 'ports': [443]}, {}),
        ]
        for item, snapshot in cases:
            with self.subTest(item=item), patch.object(notify, 'DIGEST_HOUR', 25):
                state = {}
                findings = [dict(item, delivery_class='digest', model_label='benign', triage_label='likely_household')]
                cli.triage.classify(scan.config(self.settings), findings, snapshot, {}, {}, complete=True)
                with patch.object(notify, 'send', return_value={'status': 'failed'}) as failed:
                    notify.deliver_notification(state, findings, lambda: None, now=42, level='low',
                                                approvals=[item], target=PRIVATE, stamp=STAMP)
                    failed.assert_called_once()
                with patch.object(notify, 'send', return_value={'status': 'accepted'}) as accepted:
                    notify.deliver_notification(state, [], lambda: None, now=52, level='low',
                                                approvals=[item], target=PRIVATE)
                    accepted.assert_called_once()
                    self.assertTrue(accepted.call_args.kwargs['delayed'])
                    self.assertFalse(state['notification']['pending'])

    def test_burst_crosses_scans_without_counting_repeated_names_or_other_clients(self):
        rows = [(100 + i, DEVICE, f'q{i}.example') for i in range(10)]
        counts, history = dnswatch.first_seen_bursts(rows[:5], {}, 105)
        self.assertFalse(counts)
        counts, history = dnswatch.first_seen_bursts(rows + [(110, MOVED, 'new.example')], history, 111)
        self.assertEqual(counts, {DEVICE: 10})
        self.assertFalse(dnswatch.first_seen_bursts(rows, history, 112)[0])

    def test_heartbeat_waits_a_week_after_acceptance_and_retries_failure(self):
        state = {}
        with patch.object(notify, 'DIGEST_HOUR', 25), patch.object(notify, 'send') as send:
            send.side_effect = [{'status': 'failed'}, {'status': 'accepted'}, {'status': 'accepted'}]
            for day in (0, 1, 2, 7, 8):
                notify.deliver_notification(state, [], lambda: None, now=day * 86400,
                                            target=PRIVATE, heartbeat='Monitoring is current.')
            self.assertEqual([call.kwargs['mode'] for call in send.call_args_list], ['heartbeat'] * 3)
            self.assertEqual(state['notification']['heartbeat_at'], 8 * 86400)

    def test_slow_model_has_a_wall_clock_deadline(self):
        def slow(*args, **kwargs):
            time.sleep(2)
            raise AssertionError('model deadline was ignored')
        with patch.object(model, 'chat', side_effect=slow):
            self.assertIsNone(model.device_triage(self.settings['model_url'], (443,), time.monotonic() + 0.1))

    def test_dns_credentials_are_headers_only_and_redirects_are_rejected(self):
        path = self.root / 'credential'
        path.write_text('fixture-secret')
        path.chmod(0o600)
        for provider, header in [('adguard', 'Authorization'), ('pihole', 'X-FTL-SID')]:
            source = {'provider': provider, 'host': 'server', 'credential_file': str(path)}
            with self.subTest(provider=provider), patch.object(dnswatch.http.client, 'HTTPSConnection') as connect:
                conn = connect.return_value
                conn.getresponse.return_value.__enter__.return_value.status = 302
                with self.assertRaises(ValueError):
                    dnswatch.query_page(source, SCANNER, {})
                conn.request.assert_called_once()
                self.assertIn(header, conn.request.call_args.kwargs['headers'])
                self.assertNotIn('fixture-secret', conn.request.call_args.args[1])
        with self.assertRaises(ValueError):
            scan.config(dict(self.settings, dns_api={'provider': 'pihole', 'host': 'outside-inventory'}))

    def test_valid_config_reports_missing_scan_times_when_state_is_damaged(self):
        self.settings.pop('tiers')
        self.settings_file.write_text(json.dumps(self.settings))
        for damaged in ('{', '[]'):
            (self.root / 'state.json').write_text(damaged)
            with self.subTest(damaged=damaged), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(cli.main(['status', '--json', '--config', str(self.settings_file)]), 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result['status'], 'ok')
                for profile in ('quick', 'deep'):
                    self.assertEqual(result['freshness'][profile], {'status': 'missing', 'last_success': None})
