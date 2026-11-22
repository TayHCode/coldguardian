import fcntl
from getpass import getpass
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .levels import DEFAULT_LEVEL, LEVELS
from .report import atomic_text
from .scan import command, config
from .scope import CGNAT, MIN_PREFIX_LENGTH, PRIVATE_SCOPE, ScopeError, is_private_network, tailscale_address
from .timers import check_user_manager, install_scan_timers, remove_scan_timers


def _read_json(args, result_type, optional=False):
    try:
        result = json.loads(command(args, 10))
        if isinstance(result, result_type):
            return result
    except (FileNotFoundError, subprocess.CalledProcessError):
        if optional:
            return result_type()
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    raise ScopeError(f'Could not read JSON from {" ".join(args)}')


def read_tailscale_status(*, optional=False):
    return _read_json(['tailscale', 'status', '--json'], dict, optional=optional)


def _wireguard(interface):
    kind = interface.get('linkinfo', {}).get('info_kind')
    if kind:
        return kind == 'wireguard'
    return interface.get('link_type', 'none') == 'none' and interface['ifname'].startswith('wg')


def _interface_addresses(interface):
    for row in interface['addr_info']:
        if row.get('scope') == 'global':
            yield ipaddress.ip_interface(f'{row["local"]}/{row["prefixlen"]}')


def _wireguard_networks(interfaces):
    return {
        address.network
        for interface in interfaces if _wireguard(interface)
        for address in _interface_addresses(interface)
    }


def observed_wireguard():
    return _wireguard_networks(_read_json(['ip', '-j', 'addr'], list))


def _lan_address(routes, interfaces):
    connected = {
        (route['dev'], route['dst']) for route in routes
        if route.get('scope') == 'link' and 'dev' in route and 'gateway' not in route
    }
    candidates = {}
    for interface in interfaces:
        device = interface['ifname']
        if _wireguard(interface) or device == 'tailscale0':
            continue
        for address in _interface_addresses(interface):
            network = address.network
            if network.prefixlen < MIN_PREFIX_LENGTH[network.version]:
                continue
            if network.version == 4 and (
                network.subnet_of(CGNAT) or network.prefixlen > 30 or (device, str(network)) not in connected
            ):
                continue
            if is_private_network(network):
                candidates.setdefault((device, network), address)

    defaults = sorted(
        (route for route in routes if route.get('dst') == 'default' and 'dev' in route),
        key=lambda route: route.get('metric', 0),
    )
    for route in defaults:
        matches = [a for (device, _), a in candidates.items() if device == route['dev']]
        if matches:
            gateway = ipaddress.ip_address(route['gateway']) if 'gateway' in route else None
            return _single_lan([a for a in matches if gateway is not None and gateway in a.network] or matches)
    return _single_lan(list(candidates.values()))


def _single_lan(addresses):
    ipv4 = [address for address in addresses if address.version == 4]
    addresses = ipv4 or addresses
    if len(addresses) == 1:
        return addresses[0]
    if addresses:
        raise ScopeError('Multiple LAN ranges found. Set lan_cidr explicitly')
    raise ScopeError(f'No eligible LAN range found. Set lan_cidr within {PRIVATE_SCOPE}')


def _tailscale_addresses(status):
    if status.get('BackendState', 'Running') != 'Running':
        return
    peers = status.get('Peer')
    for peer in peers.values() if peers is not None else ():
        if peer.get('ShareeNode') or peer.get('Location') is not None:
            continue
        addresses = peer.get('TailscaleIPs')
        if addresses is not None:
            if not isinstance(addresses, list):
                raise ScopeError('Each Tailscale peer must provide a list of IP addresses')
            yield from addresses


def observed_peers(*, optional=False):
    status = read_tailscale_status(optional=optional)
    if not status and optional:
        return []
    if status.get('BackendState') != 'Running' or 'Peer' not in status:
        raise ScopeError('Tailscale is not running')
    return sorted({str(tailscale_address(ip, 'Tailscale peer')) for ip in _tailscale_addresses(status)})


def detect_scope():
    routes = _read_json(['ip', '-j', 'route'], list)
    interfaces = _read_json(['ip', '-j', 'addr'], list)
    status = read_tailscale_status(optional=True)
    try:
        lan = _lan_address(routes, interfaces)
        wireguard = [str(network) for network in _wireguard_networks(interfaces)]
        peers = list(_tailscale_addresses(status))
    except ScopeError:
        raise
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ScopeError('Invalid network interface, route, or Tailscale peer data') from None

    scope = {
        'lan_cidr': str(lan.network),
        'hosts': {'scanner': str(lan.ip)},
        'local_host': 'scanner',
        'tailscale_peers': peers,
        'wireguard_subnets': wireguard,
    }
    validated = config(scope)
    return {key: validated[key] for key in scope}


def write_config(path, settings):
    validated = config(settings)
    public = {key: validated[key] for key in settings if not key.startswith('_')}
    atomic_text(Path(path), json.dumps(public, indent=2, sort_keys=True) + '\n')


def setup_config():
    return Path.home() / '.config/coldguardian/config.json'


def setup_state():
    return Path.home() / '.local/state/coldguardian'


def setup(run):
    path = setup_config()
    if path.parent.exists():
        raise ValueError(f'Setup already has a configuration directory at {path.parent}. Use coldguardian uninstall to start over.')
    if not shutil.which('nmap'):
        raise ValueError('Nmap is required. Install it with sudo apt install nmap and rerun coldguardian setup.')

    settings = detect_scope()
    print(f"LAN: {settings['lan_cidr']}")
    print(f"Scanner: {settings['hosts']['scanner']}")
    for label, field in (('Tailscale peers', 'tailscale_peers'), ('WireGuard subnets', 'wireguard_subnets')):
        print(f"{label}: {', '.join(settings[field]) or 'none'}")
    print('The first quick scan checks the scanner host. A deep scan inventories the approved LAN.')
    if input('Approve this scope? [y/N] ').strip().lower() not in ('y', 'yes'):
        print('Setup canceled.')
        return 0, 'declined'

    choice = input('Level (low, medium, high). Add "timer" for scheduling with a running systemd user manager [medium]: ').lower().split()
    level = choice[0] if choice else DEFAULT_LEVEL
    if level not in LEVELS or choice[1:] not in ([], ['timer']):
        raise ValueError('Enter low, medium, or high, optionally followed by timer.')
    if len(choice) == 2:
        print('To keep timers running after logout, enable lingering for your user.')
        check_user_manager()
    model = input('Local model URL (use a private IP or localhost), or none [none]: ').strip()
    prompt = 'ntfy server URL and topic (space-separated), or none [none]: '
    ntfy = (getpass(prompt) if sys.stdin.isatty() else input(prompt)).split()
    if ntfy in ([], ['none']):
        target = None
    elif len(ntfy) == 2:
        target = dict(zip(('server', 'topic'), ntfy))
    else:
        raise ValueError('Enter an ntfy server URL and topic, or none.')

    settings.update(level=level, output_dir=str(setup_state()),
                    model_url=None if model in ('', 'none') else model, ntfy=target)
    settings_checked = config(settings)
    path.parent.parent.mkdir(parents=True, exist_ok=True)
    path.parent.mkdir(mode=0o700)
    write_config(path, settings)
    print(f'Wrote {path}')

    def confirm():
        return input('Approve this scan as the baseline? [y/N] ').strip().lower() in ('y', 'yes')

    result = run(settings_checked, profile='quick', confirm_baseline=confirm)
    if result == 0 and len(choice) == 2:
        install_scan_timers(level)
    return result, 'ok' if result == 0 else 'incomplete'


def uninstall():
    for path in remove_scan_timers():
        print(f'Removed {path}')
    state = setup_state()
    if state.is_symlink():
        state.unlink()
        print(f'Removed {state}')
    elif state.exists():
        lockfd = os.open(state / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(lockfd, 'w') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Wait for the active scan to finish before uninstalling.') from None
            shutil.rmtree(state)
        print(f'Removed {state}')
    path = setup_config()
    if not path.parent.is_symlink() and path.parent.is_dir():
        if path.is_symlink() or path.exists():
            path.unlink()
            print(f'Removed {path}')
        if not any(path.parent.iterdir()):
            path.parent.rmdir()
    return 0
