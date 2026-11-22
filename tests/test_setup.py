import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coldguardian import cli, notify, wizard


SCOPE = {
    'lan_cidr': '10.20.30.0/24',
    'hosts': {'scanner': '10.20.30.2'},
    'local_host': 'scanner',
    'tailscale_peers': [],
    'wireguard_subnets': [],
}
NMAP_HOST = '<status state="up"/><address addr="10.20.30.2" addrtype="ipv4"/>'
NMAP_DONE = '<runstats><finished exit="success"/></runstats></nmaprun>'


class SetupTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.enterContext(patch.dict(os.environ, {'HOME': directory, 'XDG_CONFIG_HOME': directory + '/.config'}))
        self.enterContext(patch.object(wizard.shutil, 'which', return_value='/usr/bin/nmap'))
        self.enterContext(patch.object(wizard, 'detect_scope', side_effect=lambda: SCOPE.copy()))
        self.enterContext(patch.object(cli, 'open_log', side_effect=FileNotFoundError))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def scan_with(self, *answers):
        discovery = '<nmaprun><host>' + NMAP_HOST + '</host>' + NMAP_DONE
        ports = '<ports><extraports count="65534"/><port protocol="tcp" portid="22"><state state="open"/></port></ports>'
        scan = '<nmaprun><host>' + NMAP_HOST + ports + '</host>' + NMAP_DONE
        with (patch('builtins.input', side_effect=answers) as prompts,
              patch('coldguardian.scan.command', side_effect=[discovery, scan]) as nmap,
              patch('urllib.request.OpenerDirector.open') as http):
            result = cli.main(['setup'])
        http.assert_not_called()
        self.assertEqual(nmap.call_count, 2)
        self.assertEqual(prompts.call_count, len(answers))
        return result

    def test_setup_approves_displayed_scan_and_uninstall_removes_installed_files(self):
        with patch('coldguardian.timers._systemctl') as systemctl:
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
            'command': 'setup', 'status': 'declined', 'exit_code': 0,
        })
        scan.assert_not_called()
        self.assertEqual(list(Path.home().iterdir()), [])

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
