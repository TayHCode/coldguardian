import contextlib
import fcntl
import io
import json
import os
import runpy
import socket
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from coldguardian import cli, notify, wizard
from test_scan_report import SCHEMA, matches_contract


SCOPE = {
    'lan_cidr': '10.20.30.0/24',
    'hosts': {'scanner': '10.20.30.2'},
    'local_host': 'scanner',
    'tailscale_peers': [],
    'wireguard_subnets': [],
}
NMAP_HOST = '<status state="up"/><address addr="10.20.30.2" addrtype="ipv4"/>'
NMAP_DONE = '<runstats><finished exit="success"/></runstats></nmaprun>'
OUTCOME_SCHEMA = json.loads(SCHEMA.with_name('command-outcome.schema.json').read_text())


class SetupTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {'HOME': directory, 'XDG_CONFIG_HOME': directory + '/.config'}))
        self.enterContext(patch.object(wizard.shutil, 'which', return_value='/usr/bin/nmap'))
        self.enterContext(patch.object(wizard, 'detect_scope', side_effect=lambda: SCOPE.copy()))
        self.enterContext(patch.object(cli, 'open_log', side_effect=FileNotFoundError))
        self.enterContext(patch('sys.stdin', io.StringIO()))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def scan_with(self, *answers, args=('setup',)):
        discovery = '<nmaprun><host>' + NMAP_HOST + '</host>' + NMAP_DONE
        ports = '<ports><extraports count="65534"/><port protocol="tcp" portid="22"><state state="open"/></port></ports>'
        scan = '<nmaprun><host>' + NMAP_HOST + ports + '</host>' + NMAP_DONE
        with (patch('builtins.input', side_effect=answers) as prompts,
              patch('coldguardian.scan.command', side_effect=[discovery, scan]) as nmap,
              patch('urllib.request.OpenerDirector.open') as http):
            result = cli.main(list(args))
        http.assert_not_called()
        self.assertEqual(nmap.call_count, 2)
        self.assertEqual(prompts.call_count, len(answers))
        return result

    def test_setup_approves_displayed_scan_and_uninstall_removes_installed_files(self):
        with (patch('coldguardian.timers._systemctl') as systemctl,
              patch('coldguardian.timers._completed_scan_timestamp', side_effect=['baseline', 'quick', 'deep'])):
            self.assertEqual(self.scan_with('yes', 'medium timer', 'none', 'none', 'yes'), 0)
            config = Path.home() / '.config/coldguardian/config.json'
            state = Path.home() / '.local/state/coldguardian'
            units = Path.home() / '.config/systemd/user'
            self.assertIsNone(json.loads(config.read_text())['model_url'])
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertIn('Observed device at 10.20.30.2: 22', (state / 'latest.md').read_text())
            self.assertEqual(json.loads((state / 'baseline.json').read_text())['hosts'], {'10.20.30.2': [22]})
            self.assertIn('--deep', (units / 'coldguardian-deep.service').read_text())
            self.assertIn('OnCalendar=Mon *-*-* 04:00:00', (units / 'coldguardian-deep.timer').read_text())
            systemctl.assert_called_with('enable', '--now', 'coldguardian-quick.timer', 'coldguardian-deep.timer')
            self.assertEqual(cli.main(['uninstall']), 0)
            self.assertFalse(config.exists())
            self.assertFalse(state.exists())
            self.assertEqual(list(units.iterdir()), [])
            self.assertEqual(cli.main(['uninstall']), 0)

    def test_scheduled_scan_distinguishes_reported_findings_from_a_python_failure(self):
        for scan_code, service_code in ((0, 0), (1, 0), (2, 2)):
            with (self.subTest(code=scan_code), patch.object(cli, 'main', return_value=scan_code),
                  self.assertRaises(SystemExit) as exit_status):
                runpy.run_module('coldguardian.scheduled', run_name='__main__')
            self.assertEqual(exit_status.exception.code, service_code)
        with patch.object(cli, 'main', side_effect=RuntimeError), self.assertRaises(RuntimeError):
            runpy.run_module('coldguardian.scheduled', run_name='__main__')

    def test_skipped_service_cannot_reuse_the_baseline_scan(self):
        with patch('coldguardian.timers._systemctl') as systemctl:
            self.assertEqual(self.scan_with('yes', 'low timer', 'none', 'none', 'yes'), 2)
        self.assertFalse(any(call.args[0] == 'enable' for call in systemctl.call_args_list))

    def test_incomplete_scheduled_network_scan_fails_timer_opt_in(self):
        self.assertEqual(self.scan_with('yes', 'low', 'none', 'none', 'yes'), 0)
        discovery = '<nmaprun><host>' + NMAP_HOST + '</host>' + NMAP_DONE

        def run_service(*args):
            if args != ('start', 'coldguardian-quick.service'):
                return
            with (patch('sys.argv', ['scheduled', '--quick', '--config', str(wizard.setup_config())]),
                  patch('coldguardian.scan.command', side_effect=[discovery, OSError('tcp scan failed')]),
                  self.assertRaises(SystemExit) as result):
                runpy.run_module('coldguardian.scheduled', run_name='__main__')
            if result.exception.code:
                raise subprocess.CalledProcessError(result.exception.code, ['systemctl', '--user', *args])

        with (patch('builtins.input', return_value='timer'), patch.object(cli, 'peer_changes', return_value=([], [])),
              patch('coldguardian.timers._systemctl', side_effect=run_service) as systemctl):
            self.assertEqual(cli.main(['setup']), 2)
        self.assertIn('Network scan incomplete', (wizard.setup_state() / 'latest.md').read_text())
        self.assertFalse(any(call.args[0] == 'enable' for call in systemctl.call_args_list))

    def test_failed_sandboxed_scan_reports_the_unit_before_enabling_timers(self):
        def fail_deep(*args):
            if args == ('start', 'coldguardian-deep.service'):
                raise subprocess.CalledProcessError(1, ['systemctl', '--user', *args])

        with (patch('coldguardian.timers._systemctl', side_effect=fail_deep) as systemctl,
              patch('coldguardian.timers._completed_scan_timestamp', side_effect=['baseline', 'quick']),
              contextlib.redirect_stderr(io.StringIO()) as errors):
            self.assertEqual(self.scan_with('yes', 'medium timer', 'none', 'none', 'yes'), 2)
        self.assertIn('coldguardian-deep.service', errors.getvalue())
        self.assertNotIn('Enabled ', self.output.getvalue())
        self.assertFalse(any(call.args[0] == 'enable' for call in systemctl.call_args_list))
        self.assertTrue((wizard.setup_state() / 'baseline.json').is_file())

    def test_setup_declines_scope_before_writing_or_scanning(self):
        with patch('builtins.input', return_value='yuck') as prompts, patch.object(cli, 'run') as scan:
            self.assertEqual(cli.main(['setup']), 0)
        prompts.assert_called_once()
        scan.assert_not_called()
        self.assertEqual(list(Path.home().iterdir()), [])

    def test_setup_json_keeps_scope_confirmation_off_stdout(self):
        with (patch('sys.stdin', io.StringIO('no\n')),
              contextlib.redirect_stderr(io.StringIO()) as prompts,
              patch.object(cli, 'run') as scan):
            self.assertEqual(cli.main(['setup', '--json']), 0)
        self.assertIn('Approve this scope? [y/N]', prompts.getvalue())
        self.assertEqual(json.loads(self.output.getvalue()), {
            'schema_version': 1, 'command': 'setup', 'status': 'declined', 'exit_code': 0,
        })
        self.assertTrue(matches_contract(json.loads(self.output.getvalue()), OUTCOME_SCHEMA))
        scan.assert_not_called()
        self.assertEqual(list(Path.home().iterdir()), [])

    def test_setup_json_reports_ok_and_incomplete_with_scan_output_on_stderr(self):
        for answers, code, status in ((('yes', 'low', 'none', 'none', 'no'), 2, 'incomplete'),
                                      (('', 'yes'), 0, 'ok')):
            with self.subTest(status=status), contextlib.redirect_stderr(io.StringIO()) as diagnostics:
                self.output.seek(0)
                self.output.truncate()
                self.assertEqual(self.scan_with(*answers, args=('setup', '--json')), code)
                outcome = json.loads(self.output.getvalue())
                self.assertEqual(outcome, {'schema_version': 1, 'command': 'setup', 'status': status, 'exit_code': code})
                self.assertTrue(matches_contract(outcome, OUTCOME_SCHEMA))
                self.assertIn('10.20.30.2', diagnostics.getvalue())
        self.assertTrue((wizard.setup_state() / 'baseline.json').is_file())

    def uninstall_json(self, code, status):
        self.output.seek(0)
        self.output.truncate()
        with contextlib.redirect_stderr(io.StringIO()) as diagnostics:
            self.assertEqual(cli.main(['uninstall', '--json']), code)
        outcome = json.loads(self.output.getvalue())
        self.assertEqual(outcome, {'command': 'uninstall', 'status': status, 'exit_code': code})
        self.assertTrue(matches_contract(outcome, OUTCOME_SCHEMA))
        return diagnostics.getvalue()

    def test_uninstall_json_reports_each_outcome_with_removals_on_stderr(self):
        config, state = wizard.setup_config(), wizard.setup_state()
        config.parent.mkdir(parents=True)
        config.write_text('{}')
        state.mkdir(parents=True)
        with open(state / '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.assertIn('active scan', self.uninstall_json(2, 'failed'))
        self.assertTrue(config.exists())
        with patch.object(wizard, 'uninstall', side_effect=KeyboardInterrupt):
            self.assertIn('Canceled.', self.uninstall_json(2, 'canceled'))
        diagnostics = self.uninstall_json(0, 'ok')
        self.assertIn(f'Removed {state}', diagnostics)
        self.assertIn(f'Removed {config}', diagnostics)
        self.assertFalse(config.exists() or state.exists())
        self.uninstall_json(0, 'ok')

    def test_plain_uninstall_prints_removals_without_json(self):
        config = wizard.setup_config()
        config.parent.mkdir(parents=True)
        config.write_text('{}')
        self.assertEqual(cli.main(['uninstall']), 0)
        self.assertEqual(self.output.getvalue(), f'Removed {config}\n')

    def test_declining_baseline_keeps_the_report_and_leaves_timers_off(self):
        with patch('coldguardian.timers._systemctl') as systemctl:
            self.assertEqual(self.scan_with('yes', 'high timer', 'none', 'none', 'no'), 2)
        state = Path.home() / '.local/state/coldguardian'
        self.assertTrue((state / 'latest.md').is_file())
        self.assertFalse((state / 'baseline.json').exists())
        systemctl.assert_called_once_with('show', '--property=Version')

    def test_test_notification_uses_the_server_and_topic_from_setup(self):
        self.assertEqual(self.scan_with('yes', '', 'none', 'http://localhost:8080/ntfy/ example-topic', 'yes'), 0)
        self.assertFalse((Path.home() / '.config/systemd/user').exists())
        self.assertNotIn('example-topic', self.output.getvalue())
        with patch.dict(os.environ, {notify.TOPIC_ENV: str(Path.home() / 'legacy-topic')}), patch.object(
                notify.urllib.request.OpenerDirector, 'open') as send:
            response = send.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'{}'
            self.assertEqual(cli.main(['--test-notification']), 0)
        self.assertEqual(send.call_args.args[0].full_url, 'http://localhost:8080/ntfy/example-topic')

    def test_resume_preserves_settings_reports_and_approved_baseline(self):
        self.assertEqual(self.scan_with('yes', 'low', '', '', 'no'), 2)
        path = wizard.setup_config()
        state = wizard.setup_state()
        settings = path.read_bytes()
        archive, = state.glob('*Z.md')
        report = archive.read_bytes()
        with patch.object(wizard, 'detect_scope', side_effect=AssertionError):
            self.assertEqual(self.scan_with('', 'yes'), 0)
        baseline = state / 'baseline.json'
        approved = baseline.read_bytes()
        with patch('builtins.input', return_value=''), patch('coldguardian.scan.command') as nmap:
            self.assertEqual(cli.main(['setup']), 0)
        nmap.assert_not_called()
        self.assertEqual(path.read_bytes(), settings)
        self.assertEqual(baseline.read_bytes(), approved)
        self.assertEqual(archive.read_bytes(), report)

    def test_low_offers_deep_inventory_before_timer(self):
        calls = []
        def run(settings, *, profile, **kwargs):
            calls.append(profile)
            return int(profile == 'deep')
        def answer(prompt):
            if prompt.startswith('Level'):
                self.assertIn('unknown device', self.output.getvalue())
                self.assertIn('deep', prompt)
                return 'low deep timer'
            return 'yes' if 'scope' in prompt else ''
        with (patch.object(cli, 'run', side_effect=run), patch('builtins.input', side_effect=answer),
              patch.object(wizard, 'check_user_manager'), patch.object(wizard, 'install_scan_timers',
                    side_effect=lambda level, output_dir: calls.append(level))):
            self.assertEqual(cli.main(['setup']), 0)
        self.assertEqual(calls, ['quick', 'deep', 'low'])

    def test_setup_cancels_with_an_open_input_pipe(self):
        path = wizard.setup_config()
        path.parent.mkdir(parents=True)
        wizard.write_config(path, dict(SCOPE, output_dir=str(wizard.setup_state())))
        for name in ('nmap', 'ip'):
            shim = Path.home() / name
            shim.write_text('#!/bin/sh\nexit 99\n')
            shim.chmod(0o700)
        reader, writer = socket.socketpair()
        with reader, writer:
            for name, stdin in [('pipe', subprocess.PIPE), ('socket', reader)]:
                with self.subTest(stdin=name), subprocess.Popen(
                    [sys.executable, '-m', 'coldguardian.cli', 'setup', '--json'],
                    stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, env=dict(os.environ, PATH=str(Path.home())),
                ) as process:
                    try:
                        self.assertEqual(process.wait(timeout=5), 2)
                    finally:
                        process.kill()
                    outcome = json.load(process.stdout)
                    self.assertEqual(outcome, {
                        'schema_version': 1, 'command': 'setup', 'status': 'canceled', 'exit_code': 2,
                    })
                    self.assertTrue(matches_contract(outcome, OUTCOME_SCHEMA))
                    self.assertIn('status --json', process.stderr.read())
        self.assertFalse(wizard.setup_state().exists())

    def test_json_setup_accepts_a_fragmented_pipe_answer(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd) as reader, os.fdopen(write_fd, 'wb', buffering=0) as writer:
            writer.write(b'n')
            finish = threading.Timer(0.1, writer.write, args=(b'o\n',))
            finish.start()
            try:
                with patch('sys.stdin', reader), patch.object(cli, 'run') as scan:
                    self.assertEqual(cli.main(['setup', '--json']), 0)
                scan.assert_not_called()
            finally:
                finish.join()
        self.assertFalse(wizard.setup_config().exists())

    def test_plain_setup_records_a_delayed_piped_level(self):
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd) as reader, os.fdopen(write_fd, 'wb', buffering=0) as writer:
            writer.write(b'yes\n')
            finish = threading.Timer(3, writer.write, args=(b'low\nnone\nnone\n',))
            finish.start()
            try:
                with patch('sys.stdin', reader), patch.object(cli, 'run', return_value=0):
                    self.assertEqual(cli.main(['setup']), 0)
            finally:
                finish.join()
        self.assertEqual(json.loads(wizard.setup_config().read_bytes())['level'], 'low')

    def test_plain_setup_exits_on_piped_eof(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        with os.fdopen(read_fd) as reader, patch('sys.stdin', reader), patch.object(cli, 'run') as scan:
            self.assertEqual(cli.main(['setup']), 2)
        scan.assert_not_called()
        self.assertFalse(wizard.setup_config().exists())

    def test_existing_mismatched_baseline_survives_resume(self):
        self.assertEqual(self.scan_with('yes', 'low', '', '', 'yes'), 0)
        path = wizard.setup_state() / 'baseline.json'
        original = json.loads(path.read_bytes())
        original['fingerprint'] = 'previous scope'
        path.write_text(json.dumps(original))
        with (patch('builtins.input', return_value='timer'), patch.object(wizard, 'check_user_manager'),
              patch.object(wizard, 'install_scan_timers') as timers, patch('coldguardian.scan.command') as nmap):
            self.assertEqual(cli.main(['setup']), 2)
        self.assertEqual(json.loads(path.read_bytes()), original)
        nmap.assert_not_called()
        timers.assert_not_called()
