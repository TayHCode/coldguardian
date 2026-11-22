import io
import ipaddress
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from coldguardian import cli, notify, report, scan


LAN = ipaddress.IPv4Network((0x0AF17000, 29))
SCANNER, DEVICE, MOVED, OTHER = (str(LAN[i]) for i in range(1, 5))
FIXTURE = Path(__file__).parent / 'fixtures/risky_services/positive/telnet.xml'


class RetentionChurnTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.out = self.root / 'reports'
        self.out.mkdir(mode=0o700)
        self.config = self.root / 'config.json'
        self.arp = self.root / 'arp'
        self.settings = {
            'lan_cidr': str(LAN), 'hosts': {'scanner': SCANNER}, 'ports': '23,443',
            'auth_paths': [], 'output_dir': str(self.out), 'ntfy': {'server': 'https://notify.example', 'topic': 'fixture'},
        }
        self.enterContext(patch.object(scan, 'ARP_TABLE', self.arp, create=True))
        self.enterContext(patch.object(scan, 'command', side_effect=self.fixture_command))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('fixture opened a socket')))
        self.enterContext(patch('subprocess.Popen', side_effect=AssertionError('fixture spawned a program')))
        self.enterContext(patch.object(notify, 'DIGEST_HOUR', 25))
        self.transport = self.enterContext(patch('urllib.request.OpenerDirector.open'))
        response = self.transport.return_value.__enter__.return_value
        response.status = 200
        response.read.return_value = b'{}'

    def fixture_command(self, args, timeout):
        discovery = '-sn' in args
        targets = self.hosts if not discovery or self.settings['lan_cidr'] in args else [SCANNER]
        root = ET.Element('nmaprun')
        for ip in targets:
            host = ET.SubElement(root, 'host')
            ET.SubElement(host, 'status', state='up')
            ET.SubElement(host, 'address', addrtype='ipv4', addr=ip)
            if discovery:
                continue
            ports = ET.SubElement(host, 'ports')
            extra = 2
            if ip != SCANNER:
                port = ET.SubElement(ports, 'port', protocol='tcp', portid='443')
                ET.SubElement(port, 'state', state='open')
                extra -= 1
            if ip == self.risky:
                ports.append(ET.parse(FIXTURE).find('host/ports/port'))
                extra -= 1
            if extra:
                ET.SubElement(ports, 'extraports', count=str(extra), state='closed')
        ET.SubElement(ET.SubElement(root, 'runstats'), 'finished', exit='success')
        return ET.tostring(root)

    def observe(self, devices, risky=None):
        self.hosts = [SCANNER, *devices]
        self.risky = risky
        self.arp.write_text('IP address HW type Flags HW address Mask Device\n' + ''.join(
            f'{ip} 0x1 0x2 {mac} * fixture0\n' for ip, mac in devices.items()
        ))

    def run_scan(self, expected):
        self.config.write_text(json.dumps(self.settings))
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()):
            status = cli.main(['scan', '--deep', '--json', '--config', str(self.config)])
        result = json.loads(stdout.getvalue())
        self.assertEqual(status, expected, result)
        return result

    def approve(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['--approve-baseline', '--config', str(self.config)]), 0)

    def test_report_age_and_count_limits(self):
        self.settings['ntfy'] = None
        self.observe({})
        self.run_scan(2)
        self.approve()
        baseline = self.out / 'baseline.json'
        baseline_before = (baseline.read_bytes(), baseline.stat())
        now = datetime.now(timezone.utc)
        stamp_format = '%Y%m%dT%H%M%S.%fZ'
        for age in range(1, 51):
            stamp = (now - timedelta(days=age)).strftime(stamp_format)
            with report.private_file(self.out / (stamp + '.md')) as archive:
                archive.write(report.report_text([], {}, stamp))
        unrelated = self.out / ((now - timedelta(days=100)).strftime(stamp_format) + '.md')
        unrelated.write_text('Another document\n')
        unrelated.chmod(0o600)
        symlink = self.out / ((now - timedelta(days=101)).strftime(stamp_format) + '.md')
        symlink.symlink_to(baseline)
        hardlink = self.out / ((now - timedelta(days=102)).strftime(stamp_format) + '.md')
        hardlink.hardlink_to(baseline)

        def archive_names():
            return {p.name for p in self.out.glob('*Z.md') if p not in {unrelated, symlink, hardlink}}

        self.settings.update(report_max_age_days=10)
        self.run_scan(0)
        self.assertEqual(len(archive_names()), 12)
        del self.settings['report_max_age_days']
        self.settings.update(report_max_count=3)
        before_count_prune = archive_names()
        self.run_scan(0)
        archives = archive_names()
        self.assertEqual(len(archives), 3)
        self.assertEqual(archives & before_count_prune, set(sorted(before_count_prune)[-2:]))
        self.assertEqual((self.out / 'latest.md').read_bytes(), (self.out / max(archives)).read_bytes())
        self.assertEqual((baseline.read_bytes(), baseline.stat().st_mtime_ns),
                         (baseline_before[0], baseline_before[1].st_mtime_ns))
        self.assertEqual(unrelated.read_text(), 'Another document\n')
        self.assertTrue(symlink.is_symlink())
        self.assertTrue(hardlink.samefile(baseline))

    def test_default_and_configured_caps_bound_reports_and_journal(self):
        self.settings['ntfy'] = None
        self.observe({})
        self.run_scan(2)
        self.approve()
        baseline = (self.out / 'baseline.json').read_bytes()
        for cap in (report.DEFAULT_REPORT_COUNT, 3):
            if cap == 3:
                self.settings['report_max_count'] = cap
            for _ in range(cap + 2):
                latest = self.run_scan(0)
            archives = sorted(self.out.glob('*Z.md'))
            journal = [json.loads(line) for line in (self.out / 'alerts.jsonl').read_bytes().splitlines()]
            self.assertEqual(len(journal), cap)
            self.assertEqual([r['timestamp'] for r in journal], [p.stem for p in archives])
            self.assertEqual(latest['findings'][0]['finding_id'], archives[-1].stem + ':E1')
            self.assertEqual((self.out / 'latest.md').read_bytes(), archives[-1].read_bytes())
            self.assertEqual((self.out / 'baseline.json').read_bytes(), baseline)

    def test_benign_dhcp_and_random_mac_churn_with_a_risky_service(self):
        for level in ('low', 'medium'):
            with self.subTest(level=level):
                self.out = self.root / level
                self.settings.update(level=level, output_dir=str(self.out))
                self.observe({DEVICE: '02:00:00:00:00:01'})
                self.run_scan(2)
                self.approve()
                self.transport.reset_mock()

                self.observe({MOVED: '02:00:00:00:00:01'})
                result = self.run_scan(2)
                self.assertEqual(
                    [f['category'] for f in result['findings']], ['scan_summary', 'coverage', 'service'],
                )
                self.observe({DEVICE: '06:00:00:00:00:01'})
                self.run_scan(0)
                self.transport.assert_not_called()

                self.observe({MOVED: '02:00:00:00:00:01'}, risky=MOVED)
                result = self.run_scan(1)
                self.transport.assert_called_once()
                page = self.transport.call_args.args[0]
                self.assertEqual(page.get_header('Priority'), '4')
                self.assertIn(f'New device at {MOVED} has a risky service open', page.data.decode())
                self.assertEqual([(f['rule'], f['ip'], f['port']) for f in result['findings']
                                  if f['category'] == 'risky_service'], [('telnet', MOVED, 23)])

    def test_unrelated_device_with_the_same_ports_still_pages(self):
        self.observe({DEVICE: '02:00:00:00:00:01'})
        self.run_scan(2)
        self.approve()
        self.transport.reset_mock()
        self.observe({MOVED: '06:00:00:00:00:01'})
        self.run_scan(1)
        self.transport.assert_called_once()
        self.assertIn(f'New device at {MOVED}', self.transport.call_args.args[0].data.decode())

    def test_duplicate_mac_does_not_hide_a_new_ip(self):
        self.observe({DEVICE: '02:00:00:00:00:01'})
        self.run_scan(2)
        self.approve()
        self.transport.reset_mock()
        self.observe({MOVED: '02:00:00:00:00:01', OTHER: '02:00:00:00:00:01'})
        self.run_scan(1)
        self.transport.assert_called_once()
        self.assertIn(f'New device at {MOVED}', self.transport.call_args.args[0].data.decode())
