import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import migrate_guarded_config as migration


class GuardMigrationTest(unittest.TestCase):
    def setUp(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config = root / 'config.json'
        self.bindings = root / 'bindings.json'
        self.proposal = root / 'proposal.json'
        self.lan = '10.20.30.0/24'
        self.hosts = {'scanner': '10.20.30.2', 'peer': '10.20.30.3'}
        self.mac = '02:00:00:00:00:01'
        self.original = dict(lan_cidr=self.hosts['scanner'] + '/32', hosts=self.hosts, level='low')
        self.old = json.dumps(self.original) + '\r\n'
        self.config.write_bytes(self.old.encode())
        self.pins = {name: {'address': address, 'mac': self.mac} for name, address in self.hosts.items()}
        self.pins['config_sha256'] = hashlib.sha256(self.old.encode()).hexdigest()
        self.binding_text = json.dumps(self.pins)
        self.bindings.write_text(self.binding_text)
        self.new = dict(self.original, lan_cidr=self.lan, level='medium', tailscale_peers=['100.64.0.2'])
        self.proposal.touch()
        for path in (self.config, self.bindings, self.proposal):
            path.chmod(0o600)
        self.routes = [{'dev': 'lan', 'dst': self.lan, 'scope': 'link'}]
        self.devices = [{'ifname': 'lan', 'address': self.mac, 'addr_info': [
            {'family': 'inet', 'local': self.hosts['scanner'], 'prefixlen': 24}]}]
        self.enterContext(patch.object(migration, 'command', side_effect=self.metadata))
        self.enterContext(patch.object(migration.wizard, 'observed_peers', return_value=['100.64.0.2']))
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))

    def metadata(self, command, timeout):
        return json.dumps({'route': self.routes, 'addr': self.devices}[command[-1]])

    def run_migration(self, **changes):
        self.proposal.write_text(json.dumps(dict(self.new, **changes)))
        return migration.migrate(self.config, self.bindings, self.proposal, 'lan', self.lan)

    def test_valid_migration_preserves_exact_rollback_pair_and_updates_guard(self):
        backup = self.run_migration()
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup / 'config.json').read_bytes(), self.old.encode())
        self.assertEqual((backup / 'bindings.json').read_text(), self.binding_text)
        for path in (self.config, self.bindings, backup / 'config.json', backup / 'bindings.json'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        expected = dict(self.pins, config_sha256=hashlib.sha256(self.config.read_bytes()).hexdigest())
        self.assertEqual(json.loads(self.bindings.read_text()), expected)
        self.assertEqual(json.loads(self.config.read_text()), self.new)

    def test_scope_expansion_and_changes_to_unrelated_settings_are_rejected(self):
        for change in ({'level': 'high'}, {'lan_cidr': '10.20.0.0/16'},
                       {'hosts': dict(self.hosts, extra='10.20.31.1')},
                       {'wireguard_subnets': [self.lan]}, {'tailscale_peers': ['100.64.0.3']},
                       {'output_dir': str(self.config.parent)}, {'ports': '22'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_migration(**change)
            self.assertEqual(self.config.read_bytes(), self.old.encode())
            self.assertEqual(self.bindings.read_text(), self.binding_text)

    def test_routed_lan_and_changed_scanner_identity_are_rejected(self):
        self.routes[0]['gateway'] = '10.20.30.1'
        with self.assertRaises(ValueError):
            self.run_migration()
        del self.routes[0]['gateway']
        self.devices[0]['address'] = '02:00:00:00:00:02'
        with self.assertRaises(ValueError):
            self.run_migration()
        self.assertEqual(self.config.read_bytes(), self.old.encode())

    def test_modified_live_config_or_readable_proposal_is_rejected(self):
        self.proposal.chmod(0o644)
        with self.assertRaises(ValueError):
            self.run_migration()
        self.proposal.chmod(0o600)
        self.config.write_text(self.old + ' ')
        with self.assertRaises(ValueError):
            self.run_migration()
        self.assertEqual(self.bindings.read_text(), self.binding_text)

    def test_binding_write_failure_leaves_recoverable_closed_guard(self):
        write = migration.atomic_text

        def fail_binding(path, *args, **kwargs):
            if path == self.bindings:
                raise OSError('write failed')
            write(path, *args, **kwargs)

        with patch.object(migration, 'atomic_text', side_effect=fail_binding), self.assertRaises(OSError):
            self.run_migration()
        self.assertNotEqual(self.pins['config_sha256'], hashlib.sha256(self.config.read_bytes()).hexdigest())
        backup, = self.bindings.parent.glob('guard-backup-*')
        self.assertEqual((backup / 'config.json').read_bytes(), self.old.encode())
        self.assertEqual(self.bindings.read_text(), self.binding_text)
