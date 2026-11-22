import contextlib
import io
import json
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import call, patch

from coldguardian import cli, scan, wizard


FIXTURES = Path(__file__).parent / 'fixtures'
ROUTE = ['ip', '-j', 'route']
ADDR = ['ip', '-j', 'addr']
TAILSCALE = ['tailscale', 'status', '--json']
EXPECTED_SCOPE = {
    'lan_cidr': '172.22.40.0/24',
    'hosts': {'scanner': '172.22.40.11'},
    'local_host': 'scanner',
    'tailscale_peers': ['100.90.12.2', '100.90.12.3', 'fd7a:115c:a1e0::2'],
    'wireguard_subnets': ['10.73.24.0/24', 'fd00:1234:5678::/64'],
}


def fixture_outputs():
    return [
        (FIXTURES / name).read_bytes()
        for name in ('ip-route.json', 'ip-addr.json', 'tailscale-status.json')
    ]


class DetectionTests(unittest.TestCase):
    def test_read_only_command_fixtures_produce_expected_scope(self):
        with patch.object(wizard, 'command', side_effect=fixture_outputs()) as command:
            self.assertEqual(wizard.detect_scope(), EXPECTED_SCOPE)
        self.assertEqual(command.call_args_list, [call(ROUTE, 10), call(ADDR, 10), call(TAILSCALE, 10)])

    def test_missing_tailscale_keeps_lan_and_wireguard(self):
        outputs = [*fixture_outputs()[:2], FileNotFoundError('tailscale')]
        with patch.object(wizard, 'command', side_effect=outputs):
            self.assertEqual(wizard.detect_scope(), dict(EXPECTED_SCOPE, tailscale_peers=[]))

    def test_stopped_tailscale_keeps_lan_and_wireguard(self):
        stale_status = b'{"BackendState":"Stopped","Peer":{"one":{"TailscaleIPs":["100.90.12.2"]}}}'
        for status in (subprocess.CalledProcessError(1, TAILSCALE), stale_status):
            with self.subTest(status=status), patch.object(wizard, 'command', side_effect=[*fixture_outputs()[:2], status]):
                self.assertEqual(wizard.detect_scope(), dict(EXPECTED_SCOPE, tailscale_peers=[]))

    def test_tailscale_excludes_shared_and_provider_owned_peers(self):
        status = fixture_outputs()[2]
        with patch.object(wizard, 'command', side_effect=[*fixture_outputs()[:2], status]):
            self.assertEqual(wizard.detect_scope()['tailscale_peers'], EXPECTED_SCOPE['tailscale_peers'])

    def test_cgnat_uplink_is_never_proposed_as_lan(self):
        uplink_routes = [
            {'dst': 'default', 'gateway': '100.72.0.1', 'dev': 'eth0'},
            {'dst': '100.72.0.0/22', 'dev': 'eth0', 'scope': 'link'},
        ]
        uplink = {'ifname': 'eth0', 'addr_info': [{'local': '100.72.1.9', 'prefixlen': 22, 'scope': 'global'}]}
        lan_route = {'dst': '172.22.40.0/24', 'dev': 'eth1', 'scope': 'link'}
        lan = {'ifname': 'eth1', 'addr_info': [{'local': '172.22.40.11', 'prefixlen': 24, 'scope': 'global'}]}
        outputs = [json.dumps([*uplink_routes, lan_route]), json.dumps([uplink, lan]), b'{}']
        with patch.object(wizard, 'command', side_effect=outputs):
            self.assertEqual(wizard.detect_scope()['lan_cidr'], '172.22.40.0/24')
        with patch.object(wizard, 'command', side_effect=[json.dumps(uplink_routes), json.dumps([uplink]), b'{}']):
            with self.assertRaisesRegex(ValueError, 'No eligible LAN range'):
                wizard.detect_scope()

    def test_public_discovered_lan_is_rejected(self):
        for cidr, host in (('203.0.113.0/24', '203.0.113.7'), ('8.8.8.0/24', '8.8.8.8')):
            routes = [{'dst': cidr, 'dev': 'eth0', 'scope': 'link'}]
            addresses = [{'ifname': 'eth0', 'addr_info': [{'local': host, 'prefixlen': 24, 'scope': 'global'}]}]
            outputs = [json.dumps(routes), json.dumps(addresses), b'{}']
            with self.subTest(cidr=cidr), patch.object(wizard, 'command', side_effect=outputs):
                with self.assertRaisesRegex(ValueError, 'No eligible LAN range.*private scope'):
                    wizard.detect_scope()

    def test_public_discovered_peer_is_rejected(self):
        for host in ('198.51.100.8', '8.8.8.8'):
            peers = {'Peer': {'one': {'TailscaleIPs': ['100.90.12.2', host]}}}
            outputs = [*fixture_outputs()[:2], json.dumps(peers)]
            with self.subTest(host=host), patch.object(wizard, 'command', side_effect=outputs):
                with self.assertRaisesRegex(ValueError, 'tailscale_peers.*private scope'):
                    wizard.detect_scope()

    def test_ipv6_only_lan_is_proposed_without_address_expansion(self):
        addresses = b'[{"ifname":"eth0","addr_info":[{"local":"fd20:1234::7","prefixlen":64,"scope":"global"}]}]'
        with patch.object(wizard, 'command', side_effect=[b'[]', addresses, b'{}']):
            self.assertEqual(wizard.detect_scope(), {
                'lan_cidr': 'fd20:1234::/64',
                'hosts': {'scanner': 'fd20:1234::7'},
                'local_host': 'scanner',
                'tailscale_peers': [],
                'wireguard_subnets': [],
            })

    def test_detect_rejects_an_oversized_wireguard_interface_subnet(self):
        outputs = fixture_outputs()
        outputs[1] = outputs[1].replace(b'"local": "10.73.24.3", "prefixlen": 24', b'"local": "10.73.24.3", "prefixlen": 8')
        with patch.object(wizard, 'command', side_effect=outputs):
            with self.assertRaisesRegex(ValueError, 'wireguard_subnets.*prefix'):
                wizard.detect_scope()

    def test_oversized_ipv6_lan_is_not_proposed(self):
        addresses = b'[{"ifname":"eth0","addr_info":[{"local":"fd20:1234::7","prefixlen":48,"scope":"global"}]}]'
        with patch.object(wizard, 'command', side_effect=[b'[]', addresses, b'{}']):
            with self.assertRaisesRegex(ValueError, 'No eligible LAN range'):
                wizard.detect_scope()


class ConfigTests(unittest.TestCase):
    def test_accepts_only_private_families(self):
        for cidr in ('10.79.4.0/24', '172.31.4.0/24', '192.168.234.0/24', '100.127.4.0/24', 'fc00::/64'):
            with self.subTest(cidr=cidr):
                self.assertEqual(scan.config(dict(EXPECTED_SCOPE, lan_cidr=cidr))['lan_cidr'], cidr)

    def test_rejects_oversized_lan_and_wireguard_ranges(self):
        for cidr in ('10.0.0.0/8', '100.64.0.0/10', 'fc00::/7', 'fd00::/8', 'fd20::/48'):
            for key, value in (('lan_cidr', cidr), ('wireguard_subnets', [cidr])):
                with self.subTest(key=key, cidr=cidr), self.assertRaisesRegex(ValueError, f'{key}.*prefix'):
                    scan.config(dict(EXPECTED_SCOPE, **{key: value}))

    def test_tailscale_requires_exact_addresses_in_its_assigned_ranges(self):
        for address in ('192.168.77.7', 'fd00::9', '100.90.12.0/24'):
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'tailscale_peers'):
                scan.config(dict(EXPECTED_SCOPE, tailscale_peers=['100.90.12.2', address]))

    def test_rejects_public_reserved_and_partially_private_ranges(self):
        for cidr in ('8.8.8.0/24', '198.51.100.0/24', '198.18.0.0/24', '192.0.2.0/24', '127.0.1.0/24', '169.254.52.0/24',
                     '224.0.0.0/24', '240.0.0.0/24', '0.0.0.0/24', '100.0.0.0/9', '100.128.0.0/16',
                     'fe80::/64', '2001:db8::/32', '2000::/3', 'fc00::/6'):
            for key, value in (('lan_cidr', cidr), ('wireguard_subnets', ['10.73.24.0/24', cidr])):
                with self.subTest(key=key, cidr=cidr), self.assertRaisesRegex(ValueError, f'{key}.*private scope'):
                    scan.config(dict(EXPECTED_SCOPE, **{key: value}))

    def test_rejects_reserved_exact_addresses_and_invalid_types(self):
        for field, value in (
            ('lan_cidr', 'fd00::%eth0/64'), ('lan_cidr', '172.22.40.11/24'),
            ('hosts', {'scanner': '127.0.0.2'}), ('hosts', {'scanner': 167772161}),
            ('tailscale_peers', ['100.90.12.2', '203.0.113.9']),
            ('tailscale_peers', '100.90.12.2'), ('wireguard_subnets', [None]),
        ):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, field):
                scan.config(dict(EXPECTED_SCOPE, **{field: value}))

    def test_write_validated_config_and_reload_through_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / 'config.json'
            wizard.write_config(path, dict(EXPECTED_SCOPE, ports='22'))
            self.assertEqual(list(root.iterdir()), [path])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            original = path.read_bytes()
            self.assertEqual(json.loads(original), dict(EXPECTED_SCOPE, ports='22'))
            with self.assertRaisesRegex(ValueError, 'lan_cidr.*private scope'):
                wizard.write_config(path, dict(EXPECTED_SCOPE, lan_cidr='198.51.100.0/24'))
            self.assertEqual(path.read_bytes(), original)
            with patch.object(cli, 'run', return_value=0) as run:
                self.assertEqual(cli.main(['--config', str(path)]), 0)
            run.assert_called_once_with(scan.config(dict(EXPECTED_SCOPE, ports='22')), False, 'quick')

    def test_cli_explains_public_range_without_running_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(dict(EXPECTED_SCOPE, lan_cidr='198.51.100.0/24')))
            with patch.object(cli, 'run') as run, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(cli.main(['--config', str(path)]), 2)
            run.assert_not_called()
            self.assertIn('lan_cidr must be wholly within private scope', stderr.getvalue())
