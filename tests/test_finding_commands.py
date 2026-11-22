import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from coldguardian import cli, notify, report
from test_model import DNS_HIT, OPEN_PORTS, SCAN_HOST, VALID, completion, scan_settings, stub


class FindingCommandTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = self.root / 'config.json'
        self.settings = scan_settings(
            self.root, level='high',
            ntfy={'server': 'https://ntfy.sh', 'topic': 'synthetic-test-topic-0123456789'},
        )
        self.baseline = self.root / 'baseline.json'
        report.atomic_json(self.baseline, {
            'fingerprint': cli.config(self.settings)['_fingerprint'], 'hosts': {SCAN_HOST: [22]},
        })
        report.atomic_json(self.root / 'state.json', {
            'notification': {'digest_day': time.strftime('%Y-%m-%d')},
        })

    def command(self, *args):
        report.atomic_json(self.config, self.settings)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main([*args, '--config', str(self.config), '--json'])
        data = json.loads(output.getvalue())
        self.assertEqual(code, data['exit_code'])
        return code, data

    def scan(self, ports=(22, 23), logs=(DNS_HIT,)):
        with (
            patch.object(cli, 'scan', return_value=({SCAN_HOST: list(ports)}, [])),
            patch.object(cli, 'collect', return_value=({}, list(logs))),
            patch.object(cli, 'lan_macs', return_value={}),
            patch.object(cli.wizard, 'observed_peers', return_value=[]),
        ):
            return self.command('scan')

    def test_scan_is_quiet_and_explain_sends_only_selected_evidence(self):
        with (stub(completion(json.dumps(VALID))) as (url, requests),
              patch.object(notify, 'send', return_value={'status': 'accepted'}) as page):
            self.settings['model_url'] = url
            code, scan = self.scan()
            self.assertEqual(code, 1)
            self.assertEqual(requests, [])
            self.assertEqual(self.command('explain', 'E99')[0], 2)
            self.assertEqual(requests, [])
            code, result = self.command('explain', scan['findings'][1]['finding_id'])
            self.assertEqual(code, 1)
            self.assertEqual(result['explanation'], VALID)
            [(_, payload)] = requests
            self.assertEqual(json.loads(payload['messages'][1]['content']), {
                'untrusted_evidence': {'E2': OPEN_PORTS},
            })
            page.assert_called_once()

    def test_explain_informational_finding_returns_zero(self):
        explanation = dict(VALID, evidence_ids=['E3'])
        with (stub(completion(json.dumps(explanation))) as (url, requests),
              patch.object(notify, 'send', return_value={'status': 'accepted'})):
            self.settings['model_url'] = url
            self.scan(logs=({'category': 'dns_entropy', 'count': 4},))
            self.assertEqual(requests, [])
            code, result = self.command('explain', 'E3')
            self.assertEqual(code, 0)
            self.assertEqual(result['explanation'], explanation)
            self.assertEqual(len(requests), 1)

    def test_approve_records_reason_and_suppresses_only_the_repeat(self):
        with patch.object(notify, 'send', return_value={'status': 'failed', 'error_type': 'TransportError'}) as page:
            _, scan = self.scan()
            finding_id = scan['findings'][1]['finding_id']
            old = self.baseline.read_bytes()
            self.assertEqual(self.command('approve', finding_id, '--reason', '  ')[0], 2)
            self.assertEqual(self.baseline.read_bytes(), old)
            start = datetime.now(timezone.utc)
            code, result = self.command('approve', finding_id, '--reason', 'Expected device service')
            self.assertEqual(code, 0)
            approved = json.loads(self.baseline.read_text())
            [entry] = approved['approvals']
            self.assertEqual(entry['reason'], 'Expected device service')
            self.assertEqual(result['approval'], entry)
            timestamp = datetime.fromisoformat(entry['timestamp'])
            self.assertEqual(timestamp.utcoffset(), timedelta(0))
            self.assertLessEqual(start, timestamp)
            self.assertLessEqual(timestamp, datetime.now(timezone.utc))
            self.assertEqual(approved['hosts'], {SCAN_HOST: [22]})
            self.assertEqual(self.command('approve', finding_id, '--reason', 'Duplicate')[0], 1)
            page.reset_mock()
            self.scan()
            self.assertNotIn(f'New open ports on {SCAN_HOST}: 23', page.call_args.args[0])
            self.scan((22, 23, 24))
            self.assertIn(f'New open ports on {SCAN_HOST}: 23, 24', page.call_args.args[0])

    def test_restart_repairs_torn_tail_before_explain_and_approve(self):
        journal = self.root / 'alerts.jsonl'
        with (stub(completion(json.dumps(VALID))) as (url, _),
              patch.object(notify, 'send', return_value={'status': 'accepted'})):
            self.settings['model_url'] = url
            _, first = self.scan()
            with journal.open('ab') as log:
                log.write(b'{"evidence": [')
            code, later = self.scan()
            self.assertEqual(code, 1)
            rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
            self.assertEqual([row['timestamp'] for row in rows], [
                scan['findings'][0]['finding_id'].split(':')[0] for scan in (first, later)
            ])
            finding_id = later['findings'][1]['finding_id']
            for args, status in ((['explain', finding_id], 1),
                                 (['approve', finding_id, '--reason', 'Expected port'], 0)):
                result = subprocess.run([sys.executable, '-m', 'coldguardian.cli', *args,
                                         '--config', str(self.config), '--json'], capture_output=True, text=True)
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'bad' if status else 'approved')

    def test_corruption_surfaces_even_after_matching_row(self):
        with patch.object(notify, 'send', return_value={'status': 'accepted'}):
            _, first = self.scan()
        journal = self.root / 'alerts.jsonl'
        original = journal.read_bytes()
        finding_id = first['findings'][0]['finding_id']
        for damaged in (b'{"findings":\n' + original, b'garbage', b'{"bad":!', b'{}', b'\xff'):
            with self.subTest(damaged=damaged[:20]):
                journal.write_bytes(original + damaged)
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(self.command('explain', finding_id)[0], 2)
                    self.assertEqual(self.command('approve', finding_id, '--reason', 'review')[0], 2)
                    self.assertEqual(self.scan()[0], 2)
                self.assertIn('Corrupt alert journal at line 2', err.getvalue())
                self.assertEqual(journal.read_bytes(), original + damaged)

    def test_complete_last_row_without_newline_survives(self):
        with patch.object(notify, 'send', return_value={'status': 'accepted'}):
            _, first = self.scan()
            journal = self.root / 'alerts.jsonl'
            journal.write_bytes(journal.read_bytes().rstrip(b'\n'))
            self.scan()
        self.assertEqual(len(journal.read_text().splitlines()), 2)
        self.assertEqual(report.saved_finding(self.root, first['findings'][1]['finding_id'])[1], 'E2')

    def test_approval_window_survives_management_reports_then_expires(self):
        self.settings.update(report_max_count=1, ntfy=None)
        _, first = self.scan()
        finding_id = first['findings'][1]['finding_id']
        pinned = self.root / (finding_id.split(':')[0] + '.md')
        for _ in range(3):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['--approve-baseline', '--config', str(self.config)]), 0)
            self.assertTrue(pinned.is_file())
            self.assertEqual(len(list(self.root.glob('*Z.md'))), 2)
            self.assertEqual(len((self.root / 'alerts.jsonl').read_text().splitlines()), 2)
        self.assertEqual(self.command('approve', finding_id, '--reason', 'Expected port')[0], 0)
        self.scan()
        self.assertFalse(pinned.exists())
        self.assertEqual(len((self.root / 'alerts.jsonl').read_text().splitlines()), 1)
        for args in (['explain', finding_id], ['approve', finding_id, '--reason', 'review']):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code, data = self.command(*args)
            self.assertEqual((code, data['error_type']), (2, 'FindingExpired'))
            self.assertIn('expired', err.getvalue())

    def test_age_limit_keeps_pending_scan_until_state_commit_succeeds(self):
        self.settings.update(report_max_age_days=1, ntfy=None)
        with patch.object(report.datetime, 'datetime', wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
            _, first = self.scan()
        finding_id = first['findings'][1]['finding_id']
        state = self.root / 'state.json'
        before = state.read_bytes()
        write_json = cli.atomic_json

        def fail_state(path, value):
            if path == state:
                raise OSError('state write failed')
            write_json(path, value)

        with (patch.object(cli, 'atomic_json', side_effect=fail_state),
              patch.object(report.datetime, 'datetime', wraps=datetime) as clock):
            clock.now.return_value = datetime(2026, 1, 3, tzinfo=timezone.utc)
            self.assertEqual(self.scan()[0], 2)
        self.assertEqual(state.read_bytes(), before)
        self.assertEqual(self.command('approve', finding_id, '--reason', 'Expected port')[0], 0)
        with patch.object(report.datetime, 'datetime', wraps=datetime) as clock:
            clock.now.return_value = datetime(2026, 1, 4, tzinfo=timezone.utc)
            self.scan()
        with self.assertRaises(report.FindingExpired):
            report.saved_finding(self.root, finding_id)

    def test_retained_superseded_scan_cannot_be_approved(self):
        self.settings['ntfy'] = None
        _, first = self.scan()
        self.scan()
        finding_id = first['findings'][1]['finding_id']
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(self.command('approve', finding_id, '--reason', 'review')[0], 2)
        self.assertIn('latest scan', err.getvalue())

    def test_every_prefix_of_a_serialized_final_record_is_recoverable(self):
        self.settings['ntfy'] = None
        _, scan = self.scan()
        finding_id = scan['findings'][1]['finding_id']
        journal = self.root / 'alerts.jsonl'
        original = journal.read_bytes()
        tail = json.dumps({
            'findings': [{'category': 'service', 'product': 'caf\u00e9', 'complete': False}],
            'timestamp': '20260102T030405.123456Z',
        }).encode()
        for end in range(1, len(tail)):
            with self.subTest(end=end):
                journal.write_bytes(original + tail[:end])
                self.assertEqual(report.saved_finding(self.root, finding_id)[1], 'E2')

    def test_baseline_approval_rejects_corrupt_journal_before_writing(self):
        self.settings['ntfy'] = None
        self.scan()
        before = self.baseline.read_bytes()
        with (self.root / 'alerts.jsonl').open('ab') as journal:
            journal.write(b'garbage\n')
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(cli.main(['--approve-baseline', '--config', str(self.config)]), 2)
        self.assertIn('Corrupt alert journal', err.getvalue())
        self.assertEqual(self.baseline.read_bytes(), before)

    def test_error_report_survives_invalid_state(self):
        self.settings['ntfy'] = None
        report.atomic_json(self.config, self.settings)
        for state in ('{', '[]'):
            with self.subTest(state=state):
                (self.root / 'state.json').write_text(state)
                with patch.object(cli, 'run', side_effect=OSError()), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(['--config', str(self.config)]), 2)
                self.assertEqual((self.root / 'state.json').read_text(), state)
                [row] = (self.root / 'alerts.jsonl').read_text().splitlines()
                self.assertEqual(json.loads(row)['findings'][0]['component'], 'configuration_or_io')
                (self.root / 'alerts.jsonl').unlink()
