from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coldguardian import cli, hostwatch, model, notify, scan, timers
from test_retention_churn import LAN, SCANNER
from test_scan_report import matches_contract, SCHEMA


LISTENERS = (b'tcp LISTEN 0 128 0.0.0.0:8080 0.0.0.0:* users:(("server",pid=21,fd=3),("worker",pid=22,fd=3))\n'
             b'udp UNCONN 0 0 [::]:5353 [::]:* users:(("worker",pid=22,fd=5))\n')
KEYS = 'home/fixture/.ssh/authorized_keys'
CRON = 'var/spool/cron/crontabs/fixture'
UNIT = 'etc/systemd/system/sample.service'
TIMER = 'etc/systemd/system/sample.timer'


class HostWatchTests(unittest.TestCase):
    def setUp(self):
        base = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.root, self.out, self.config = base / 'machine', base / 'reports', base / 'config'
        self.out.mkdir()
        self.root.mkdir()
        self.settings = dict(lan_cidr=str(LAN), hosts={'scanner': SCANNER}, local_host='scanner',
                             host_watch=True, level='low', ports='443', tiers={'servers': ['scanner'], 'household': 'lan'},
                             output_dir=str(self.out), auth_paths=[], ntfy={'server': 'https://notify.example', 'topic': 'fixture'})
        self.enterContext(patch.object(hostwatch, 'ROOT', self.root))
        self.ss = self.enterContext(patch.object(hostwatch, 'command', return_value=LISTENERS))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('unexpected network access')))
        self.enterContext(patch('subprocess.run', side_effect=AssertionError('unexpected process')))
        self.enterContext(patch.object(model, 'device_triage', side_effect=AssertionError('unexpected model')))
        self.enterContext(patch.object(cli, 'scan', return_value=({SCANNER: [443]}, [])))
        self.enterContext(patch.object(cli, 'lan_macs', return_value={}))
        self.enterContext(patch.object(cli, 'collect', return_value=({}, [])))
        self.send = self.enterContext(patch.object(notify, 'send', return_value={'status': 'accepted'}))
        for pid in (21, 22):
            exe = self.root / 'proc' / str(pid) / 'exe'
            exe.parent.mkdir(parents=True)
            exe.symlink_to('/usr/bin/fixture')
        for path in (KEYS, CRON, UNIT, TIMER):
            self.write(path, 'private fixture contents')

    def write(self, path, content):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content)
        return file

    def run_cli(self, *args):
        self.config.write_text(json.dumps(self.settings))
        with redirect_stdout(io.StringIO()) as out:
            code = cli.main(['--config', str(self.config), *args])
        return code, out.getvalue()

    def scan(self, code, profile='quick'):
        actual, output = self.run_cli('scan', '--' + profile, '--json')
        self.assertEqual(actual, code, output)
        doc = json.loads(output)
        self.assertTrue(matches_contract(doc, json.loads(SCHEMA.read_text())))
        return doc['findings']

    def approve(self):
        self.scan(2)
        self.assertEqual(self.run_cli('--approve-baseline')[0], 0)

    def status(self, expected):
        code, raw = self.run_cli('status', '--json')
        self.assertEqual(code, expected, raw)
        doc = json.loads(raw)
        schema = json.loads(SCHEMA.with_name('command-outcome.schema.json').read_text())
        self.assertTrue(matches_contract(doc, schema))
        return doc

    def test_all_listeners_and_empty_or_unknown_attribution(self):
        self.assertEqual(self.status(2)['host_watch']['scope'], hostwatch.SCOPE)
        self.approve()
        rows = [r for r in self.scan(0) if r['category'] == 'host_listener']
        self.ss.assert_called_with(['ss', '-H', '-tulpn'], 10)
        self.assertEqual([(r['address'], r['port'], r['protocol'], r['process'], r['pid'], r['binary']) for r in rows], [
            ('0.0.0.0', 8080, 'tcp', 'server', 21, '/usr/bin/fixture'),
            ('0.0.0.0', 8080, 'tcp', 'worker', 22, '/usr/bin/fixture'),
            ('[::]', 5353, 'udp', 'worker', 22, '/usr/bin/fixture')])
        self.status(0)
        self.assertIsNotNone(timers._completed_scan_timestamp(self.out / 'state.json'))
        self.assertIn('this machine only', (self.out / 'latest.md').read_text())
        self.ss.return_value = b'tcp LISTEN 0 128 *:8080 *:*\n'
        row, = [r for r in self.scan(2) if r['category'] == 'host_listener']
        self.assertEqual(row['port'], 8080)
        self.assertNotIn('pid', row)
        self.assertEqual(timers._completed_scan_timestamp(self.out / 'state.json'),
                         json.loads((self.out / 'state.json').read_text())['report_timestamp'])
        self.assertEqual(self.status(2)['host_watch']['status'], 'incomplete')
        for value in (b'tcp ESTAB 0 0 1:1 2:2', b'malformed', b'\xff'):
            self.ss.return_value = value
            self.assertFalse(any(r['category'] == 'host_listener' for r in self.scan(2)))
        self.ss.return_value = b''
        self.scan(0)
        self.ss.side_effect = PermissionError()
        self.scan(2)

    def test_drift_pages_even_during_gaps_and_stores_only_hashes(self):
        self.approve()
        self.scan(0)
        self.send.reset_mock()
        before = json.loads((self.out / 'baseline.json').read_text())['persistence']
        self.assertEqual(before, {'/' + p: hashlib.sha256(b'private fixture contents').hexdigest()
                                  for p in (KEYS, CRON, UNIT, TIMER)})
        for path in (KEYS, CRON, UNIT, TIMER, 'etc/cron.d/newjob'):
            self.write(path, 'private replacement')
        (self.root / 'proc/21/exe').unlink()
        (self.root / 'etc/cron.d/bad').symlink_to('/unwatched')
        findings = self.scan(1)
        rows = [r for r in findings if r['category'] == 'persistence_drift']
        self.assertEqual({r['path']: r['change'] for r in rows},
                         {**{p: 'changed' for p in before}, '/etc/cron.d/newjob': 'added', '/etc/cron.d/bad': 'added'})
        self.assertEqual({r['delivery_class'] for r in rows}, {'hard_page'})
        self.assertEqual({r['component'] for r in findings if r['category'] == 'coverage'},
                         {'host_persistence', 'host_listeners'})
        self.assertTrue(any('mode' not in c.kwargs for c in self.send.call_args_list))
        self.assertEqual(before, json.loads((self.out / 'baseline.json').read_text())['persistence'])
        self.assertEqual(self.run_cli('approve', rows[0]['finding_id'], '--reason', 'fixture')[0], 2)
        self.assertEqual(self.run_cli('--approve-baseline')[0], 0)
        self.assertEqual(json.loads((self.out / 'baseline.json').read_text())['persistence'],
                         {row['path']: row['sha256'] for row in rows})
        for file in self.out.iterdir():
            self.assertNotIn(b'private fixture contents', file.read_bytes())
            self.assertNotIn(b'private replacement', file.read_bytes())
        self.assertNotIn('private replacement', repr(self.send.call_args_list))

    def test_nonserver_drift_and_resolved_then_reopened_server_drift(self):
        self.approve()
        self.settings['tiers']['servers'] = []
        self.write(KEYS, 'new')
        self.send.reset_mock()
        row, = [r for r in self.scan(1) if r['category'] == 'persistence_drift']
        self.assertNotIn('delivery_class', row)
        self.assertFalse(any('mode' not in c.kwargs for c in self.send.call_args_list))
        self.settings['tiers']['servers'] = ['scanner']
        for content, code in [('new', 1), ('new', 1), ('private fixture contents', 0), ('new', 1)]:
            self.write(KEYS, content)
            self.scan(code)
        self.assertEqual(sum('mode' not in c.kwargs for c in self.send.call_args_list), 2)

    def test_disable_preserves_network_reference_and_runs_no_collector(self):
        self.approve()
        self.ss.reset_mock()
        with patch.object(hostwatch, 'persistence', side_effect=AssertionError('unexpected filesystem read')):
            for enabled in (False, None):
                self.settings['host_watch'] = enabled
                if enabled is None:
                    del self.settings['host_watch']
                self.scan(0)
                self.assertNotIn('host_watch', self.status(0))
            self.ss.assert_not_called()
        for settings in (dict(self.settings, host_watch='false'), dict(self.settings, host_watch=True, local_host=None)):
            with self.assertRaises(ValueError):
                scan.config(settings)

    def test_enable_with_existing_network_baseline_needs_explicit_enrollment(self):
        self.settings['host_watch'] = False
        self.approve()
        self.settings['host_watch'] = True
        findings = self.scan(2)
        self.assertEqual({f['component'] for f in findings if f['category'] == 'coverage'}, {'host_baseline'})
        self.assertFalse(any(f['category'] == 'persistence_drift' for f in findings))
        self.assertEqual(self.run_cli('--approve-baseline')[0], 0)
        self.scan(0)
        self.settings['host_watch'] = False
        self.scan(0)
        self.assertEqual(self.run_cli('--approve-baseline')[0], 0)
        self.settings['host_watch'] = True
        self.write(KEYS, 'changed while disabled')
        self.scan(1)

    def deny_root(self):
        open_file = os.open

        def restricted(path, *args, **kwargs):
            if path == 'root' and 'dir_fd' in kwargs:
                raise PermissionError()
            return open_file(path, *args, **kwargs)
        return patch.object(os, 'open', side_effect=restricted)

    def test_permission_denied_preserves_network_completion_and_pages_readable_drift(self):
        self.write('root/.ssh/authorized_keys', 'inaccessible fixture')
        self.settings['level'] = 'medium'
        with self.deny_root():
            self.approve()
            baseline = json.loads((self.out / 'baseline.json').read_text())
            self.assertEqual(baseline['hosts'], {SCANNER: [443]})
            self.assertEqual(set(baseline['persistence']), {'/' + path for path in (KEYS, CRON, UNIT, TIMER)})
            previous = timers._completed_scan_timestamp(self.out / 'state.json')
            self.assertIsNotNone(previous)
            for profile in ('quick', 'deep'):
                for now in (100, 200):
                    with patch('time.time', return_value=now):
                        rows = self.scan(2, profile)
                        status = self.status(2)
                    self.assertEqual({r['component'] for r in rows if r['category'] == 'coverage'},
                                     {'host_persistence'})
                    self.assertEqual(status['host_watch']['status'], 'incomplete')
                    self.assertEqual(status['freshness'][profile], {'status': 'fresh', 'last_success': now})
                    current = timers._completed_scan_timestamp(self.out / 'state.json')
                    self.assertIsNotNone(current)
                    self.assertNotEqual(current, previous)
                    previous = current
            self.write(KEYS, 'updated fixture')
            self.send.reset_mock()
            rows = self.scan(1)
            drift, = [r for r in rows if r['category'] == 'persistence_drift']
            self.assertEqual((drift['path'], drift['delivery_class']), ('/' + KEYS, 'hard_page'))
            self.assertTrue(any('mode' not in call.kwargs for call in self.send.call_args_list))
            self.assertEqual(self.status(2)['host_watch']['status'], 'incomplete')
            self.write(KEYS, 'private fixture contents')
            with patch.object(cli, 'scan', return_value=({}, [scan.finding('coverage', component='tcp_scan')])):
                self.scan(2)
            self.assertIsNone(timers._completed_scan_timestamp(self.out / 'state.json'))
            self.assertEqual(self.run_cli('--approve-baseline')[0], 2)
            self.assertEqual(json.loads((self.out / 'baseline.json').read_text()), baseline)

    def test_disabling_before_approval_preserves_prior_persistence_reference(self):
        self.approve()
        self.write(KEYS, 'changed since enrollment')
        self.scan(1)
        self.settings['host_watch'] = False
        self.assertEqual(self.run_cli('--approve-baseline')[0], 0)
        self.settings['host_watch'] = True
        row, = [f for f in self.scan(1) if f['category'] == 'persistence_drift']
        self.assertEqual(row['delivery_class'], 'hard_page')

    def test_partial_reapproval_retains_unreadable_reference_until_visible_again(self):
        hidden = 'root/.ssh/authorized_keys'
        self.write(hidden, 'prior fixture')
        self.approve()
        self.write(hidden, 'unseen edit')
        with self.deny_root():
            self.scan(2)
            self.assertEqual(self.run_cli('--approve-baseline')[0], 0)
            current = json.loads((self.out / 'state.json').read_text())['snapshot']
            self.assertNotIn('/' + hidden, current['persistence'])
        row, = [f for f in self.scan(1) if f['category'] == 'persistence_drift']
        self.assertEqual((row['path'], row['change'], row['delivery_class']), ('/' + hidden, 'changed', 'hard_page'))

    def test_setup_with_deep_inventory_and_timers_under_partial_host_coverage(self):
        self.settings['level'] = 'medium'
        self.config.write_text(json.dumps(self.settings))

        def systemctl(*args):
            if args[0] == 'start':
                profile = args[1].removeprefix('coldguardian-').removesuffix('.service')
                self.assertEqual(self.run_cli('--' + profile)[0], 1)
        with (self.deny_root(), patch.object(cli.wizard, 'setup_config', return_value=self.config),
              patch('builtins.input', side_effect=['deep timer', 'yes']),
              patch('shutil.which', return_value='/fixture/program'),
              patch.object(timers, '_systemctl', side_effect=systemctl) as manager,
              patch.object(timers, '_unit_directory', return_value=self.out / 'units')):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(['setup']), 0)
        manager.assert_called_with('enable', '--now', 'coldguardian-quick.timer', 'coldguardian-deep.timer')
        self.assertEqual(self.status(2)['host_watch']['status'], 'incomplete')

    def test_symlinks_special_files_and_unit_dropins(self):
        self.write('etc/systemd/system/sample.service.d/limits.conf', 'private dropin')
        self.write('var/spool/cron/fixture', 'private crontab')
        self.write('lib/systemd/system/vendor.timer', 'private vendor unit')
        ref = self.root / 'etc/systemd/system/multi-user.target.wants/sample.service'
        ref.parent.mkdir()
        ref.symlink_to('../sample.service')
        files, complete = hostwatch.persistence()
        self.assertTrue(complete)
        self.assertIn('/etc/systemd/system/multi-user.target.wants/sample.service', files)
        self.assertIn('/etc/systemd/system/sample.service.d/limits.conf', files)
        self.assertIn('/var/spool/cron/fixture', files)
        self.assertIn('/lib/systemd/system/vendor.timer', files)
        os.mkfifo(self.root / 'etc/systemd/system/pipe.timer')
        (self.root / 'home/linked-account').symlink_to(self.root.parent)
        self.assertFalse(hostwatch.persistence()[1])
