"""Migrate a guarded Low install to an explicitly approved Medium configuration."""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import stat
import tempfile

from coldguardian import wizard
from coldguardian.feeds import source_id
from coldguardian.report import atomic_text
from coldguardian.scan import command, config


def private_text(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError('Expected a private, owner-only regular file.')
        return source.read().decode('utf-8')


def validate_change(old, new, bindings, interface, lan):
    scanner = bindings['scanner']
    hosts = {name: bindings[name]['address'] for name in ('scanner', 'peer')}
    network = ipaddress.IPv4Network(lan)
    if (old.get('level') != 'low' or old.get('lan_cidr') != hosts['scanner'] + '/32'
            or old.get('hosts') != hosts or old.get('tailscale_peers') or old.get('wireguard_subnets')
            or new.get('level') != 'medium' or new.get('lan_cidr') != str(network)
            or network.prefixlen != 24 or any(ipaddress.IPv4Address(ip) not in network.hosts() for ip in hosts.values())):
        raise ValueError('Unexpected source or destination scope.')
    changed = {key for key in old.keys() | new.keys() if (key in old, old.get(key)) != (key in new, new.get(key))}
    if changed - {'level', 'lan_cidr', 'tailscale_peers', 'model_url', 'ntfy', 'feed'}:
        raise ValueError('Only the level, approved scope and alert settings may change.')
    checked = config(new)
    if new.get('feed') is not None:
        source_id(new['feed'])
    routes = json.loads(command(['ip', '-j', 'route'], 10))
    if not any(row.get('dev') == interface and row.get('dst') == lan and row.get('scope') == 'link'
               and not {'gateway', 'via'} & row.keys() for row in routes):
        raise ValueError('Approved LAN is not directly connected.')
    interfaces = json.loads(command(['ip', '-j', 'addr'], 10))
    if not any(dev.get('ifname') == interface and dev.get('address') == scanner['mac']
               and any(addr.get('family') == 'inet' and addr.get('local') == hosts['scanner']
                       and addr.get('prefixlen') == network.prefixlen for addr in dev['addr_info'])
               for dev in interfaces):
        raise ValueError('Scanner identity or LAN prefix changed.')
    if 'tailscale_peers' not in new or not set(checked['tailscale_peers']) <= set(wizard.observed_peers()):
        raise ValueError('Selected peers must be explicitly listed and currently eligible.')


def migrate(config_path, bindings_path, proposal_path, interface, lan):
    directory = os.open(bindings_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        old_text = private_text(config_path)
        binding_text = private_text(bindings_path)
        proposed_text = private_text(proposal_path)
        bindings = json.loads(binding_text)
        if bindings['config_sha256'] != hashlib.sha256(old_text.encode()).hexdigest():
            raise ValueError('Current configuration does not match its guard.')
        validate_change(json.loads(old_text), json.loads(proposed_text), bindings, interface, lan)
        backup = Path(tempfile.mkdtemp(prefix='guard-backup-', dir=bindings_path.parent))
        atomic_text(backup / 'config.json', old_text, create_only=True)
        atomic_text(backup / 'bindings.json', binding_text, create_only=True)
        print(f'Rollback copies in {backup}', flush=True)
        atomic_text(config_path, proposed_text)
        bindings['config_sha256'] = hashlib.sha256(proposed_text.encode()).hexdigest()
        atomic_text(bindings_path, json.dumps(bindings, indent=2) + '\n')
        return backup
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--bindings', type=Path, required=True)
    parser.add_argument('--proposal', type=Path, required=True)
    parser.add_argument('--interface', required=True)
    parser.add_argument('--lan', required=True)
    args = parser.parse_args()
    migrate(args.config, args.bindings, args.proposal, args.interface, args.lan)


if __name__ == '__main__':
    main()
