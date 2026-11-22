import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from coldguardian import notify
from coldguardian.scan import config, finding


class LevelTests(unittest.TestCase):
    def test_one_set_of_findings_has_three_page_sets(self):
        risky_device = '192.0.2.10'
        ordinary_device = '192.0.2.11'
        findings = [
            finding('dns_feed_match', domain='bad.example'),
            finding('link_feed_hit', url='https://bad.example/path'),
            finding('login_burst', count=8),
            finding('new_device', ip=risky_device),
            finding('new_device', ip=ordinary_device),
            finding('new_ports', ip=risky_device, ports=[23], model_label='benign'),
            finding('risky_service', ip=risky_device, ports=[23], model_label='benign'),
            finding('risky_service', ip='192.0.2.12', ports=[21]),
            finding('peer_change'),
            finding('baseline_missing'),
            finding('baseline_mismatch'),
            finding('baseline_drift'),
            finding('coverage', component='tcp_scan'),
            finding('dns_entropy', count=2, model_label='needs_human'),
            finding('dns_suffix', count=1, model_label='risk'),
            finding('auth_failed', count=1),
            finding('scan_summary'),
        ]
        low = {
            'DNS queries matched the local feed',
            'Known-bad link match',
            'Failed sign-in burst',
            'New device at 192.0.2.10 has a risky service open',
        }
        medium = low | {
            'New device at 192.0.2.11',
            'New open ports on 192.0.2.10: 23',
            'Risky service on 192.0.2.10',
            'Risky service on 192.0.2.12',
            'Peer change',
            'No approved network reference exists. Review the report, then approve one.',
            'The network reference no longer matches the configuration. Review the report.',
        }
        high = medium | {
            'Baseline drift',
            'Monitoring gap: tcp scan',
            'High-entropy DNS labels',
        }
        for level, expected in {'low': low, 'medium': medium, 'high': high}.items():
            with self.subTest(level=level), patch.dict(os.environ, {notify.TOPIC_ENV: 'unused'}), patch.object(notify, 'DIGEST_HOUR', 0), patch.object(notify, 'send', return_value={'status': 'accepted'}) as send:
                notify.deliver_notification({}, findings, lambda: None, now=100, level=level)
                page, digest = send.call_args_list
                self.assertEqual(set(page.args[0]), expected)
                self.assertEqual(digest.kwargs, {'mode': 'digest'})
                self.assertIn('Configured DNS suffix matches', digest.args[0])
                self.assertIn('Failed sign-ins', digest.args[0])

    def test_retry_uses_current_level_and_keeps_lower_level_pages(self):
        state = {'notification': {'pending': {'baseline_missing': 'Legacy baseline page'}}}
        findings = [finding('new_device', ip='192.0.2.10'), finding('dns_feed_match')]
        failure = {'status': 'failed', 'error_type': 'TransportError'}
        with patch.dict(os.environ, {notify.TOPIC_ENV: 'unused'}), patch.object(notify, 'DIGEST_HOUR', 25):
            with patch.object(notify, 'send', return_value=failure) as send:
                notify.deliver_notification(state, findings, lambda: None, now=100, level='high')
                send.assert_called_once_with(
                    ['DNS queries matched the local feed', 'Legacy baseline page', 'New device at 192.0.2.10'],
                    delayed=True,
                )
            with patch.object(notify, 'send', return_value={'status': 'accepted'}) as send:
                notify.deliver_notification(state, [], lambda: None, now=200, level='low')
                send.assert_called_once_with(['DNS queries matched the local feed'], delayed=True)
            self.assertIn('new_device:192.0.2.10', state['notification']['digest'])
            self.assertEqual(state['notification']['pending'], {})

    def test_setup_timer_files_and_deep_port_ranges(self):
        from coldguardian.levels import LEVELS
        from coldguardian.timers import write_scan_timers

        cases = {
            'low': ('*-*-* 08:00:00', None, 1000),
            'medium': ('*-*-* 08:00:00', 'Mon *-*-* 04:00:00', None),
            'high': ('*-*-* 02/6:00:00', '*-*-* 04:00:00', None),
        }
        for level, (quick, deep, ports) in cases.items():
            with self.subTest(level=level), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.assertEqual(write_scan_timers(root, level), ())
                self.assertEqual(list(root.iterdir()), [])
                written = write_scan_timers(root, level, enabled=True)
                expected = {'quick': quick, **({'deep': deep} if deep else {})}
                self.assertEqual({path.name for path in root.iterdir()}, {f'coldguardian-{profile}.timer' for profile in expected})
                self.assertEqual(set(written), set(root.iterdir()))
                for profile, calendar in expected.items():
                    lines = (root / f'coldguardian-{profile}.timer').read_text().splitlines()
                    self.assertIn(f'Unit=coldguardian-{profile}.service', lines)
                    self.assertIn('Persistent=true', lines)
                    self.assertEqual([line for line in lines if line.startswith('OnCalendar=')], [f'OnCalendar={calendar}'])
                self.assertEqual(LEVELS[level].deep_top_ports, ports)

    def test_level_defaults_to_medium_without_invalidating_the_baseline(self):
        raw = {'lan_cidr': '10.0.0.0/30', 'hosts': {'scanner': '10.0.0.1'}}
        default = config(raw)
        self.assertEqual(default['level'], 'medium')
        for level in ('low', 'medium', 'high'):
            with self.subTest(level=level):
                self.assertEqual(config(dict(raw, level=level))['_fingerprint'], default['_fingerprint'])
        for bad in ('', 'High', [], None):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'level must be low, medium or high'):
                config(dict(raw, level=bad))
