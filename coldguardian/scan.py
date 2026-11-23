import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import xml.etree.ElementTree as ET

from . import dnswatch, rules, triage
from .endpoints import validate_ntfy
from .levels import DEFAULT_LEVEL, validate_level
from .model import endpoint
from .scope import (
    MIN_PREFIX_LENGTH, ScopeError, check_snapshot_scope, is_private_network, private_address,
    private_network, tailscale_address, usable_address,
)


HOST_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}')
MAC_ADDRESS = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')
ARP_TABLE = Path('/proc/net/arp')


def valid_mac(value):
    return (isinstance(value, str) and MAC_ADDRESS.fullmatch(value)
            and value != '00:00:00:00:00:00' and not (int(value[:2], 16) & 1))


def lan_macs(snapshot, network):
    try:
        rows = ARP_TABLE.read_text().splitlines()[1:]
    except (OSError, UnicodeError):
        return {}
    by_ip = {}
    for row in rows:
        fields = row.split()
        if len(fields) != 6:
            continue
        ip, kind, flags, mac, _, _ = fields
        if kind == '0x1' and flags == '0x2' and ip in snapshot and ipaddress.ip_address(ip) in network:
            by_ip.setdefault(ip, []).append(mac.lower())
    return {ip: macs[0] for ip, macs in by_ip.items() if len(macs) == 1 and valid_mac(macs[0])}


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def config(raw):
    c = dict(raw)
    lan = private_network(c.get('lan_cidr'), 'lan_cidr')
    if lan.version == 4 and lan.prefixlen == 31:
        raise ScopeError('IPv4 lan_cidr must have a prefix of /30 or shorter, or be an exact /32')
    c['lan_cidr'] = str(lan)
    c['_lan'] = lan
    for field, parse in (('tailscale_peers', tailscale_address), ('wireguard_subnets', private_network)):
        if field in c:
            if not isinstance(c[field], list):
                raise ScopeError(f'{field} must be a list')
            c[field] = sorted({str(parse(value, field)) for value in c[field]})
    c['_tailscale_ipv4'] = {ip for ip in c.get('tailscale_peers', ()) if ':' not in ip}
    c['_wireguard_ipv4'] = tuple(
        ipaddress.IPv4Network(cidr) for cidr in c.get('wireguard_subnets', ()) if ':' not in cidr
    )
    inventory = c.get('hosts')
    if not isinstance(inventory, dict) or not inventory or not all(isinstance(n, str) and HOST_NAME.fullmatch(n) for n in inventory):
        raise ValueError('hosts must map valid host names to exact private IP addresses')
    inventory = {name: str(private_address(address, 'hosts')) for name, address in inventory.items()}
    c['hosts'] = inventory
    if 'dns_api' in c:
        dnswatch.validate(c['dns_api'], inventory)
    if 'tiers' in c:
        c['_servers'] = triage.server_addresses(c['tiers'], inventory)
    if len(set(inventory.values())) != len(inventory):
        raise ValueError('host addresses must be unique')
    if lan.prefixlen == 32 and str(lan.network_address) not in inventory.values():
        raise ScopeError('IPv4 /32 lan_cidr must match an address in hosts')
    c.setdefault('ports', '1-65535')
    ports = set()
    if not isinstance(c['ports'], str) or not re.fullmatch(r'\d+(?:-\d+)?(?:,\d+(?:-\d+)?)*', c['ports']):
        raise ValueError('invalid ports')
    for span in c['ports'].split(','):
        ends = list(map(int, span.split('-')))
        lo, hi = ends[0], ends[-1]
        if not 1 <= lo <= hi <= 65535:
            raise ValueError('invalid ports')
        ports.update(range(lo, hi + 1))
    c['_port_count'] = len(ports)
    c['_ports'] = ports
    c.setdefault('output_dir', '/var/lib/coldguardian')
    if not isinstance(c['output_dir'], str) or not Path(c['output_dir']).is_absolute():
        raise ValueError('output_dir must be absolute')
    retention = {}
    for name in ('max_age_days', 'max_count'):
        field = 'report_' + name
        if field in c:
            value = c[field]
            if type(value) is not int or value < 1:
                raise ValueError(f'{field} must be a positive integer')
            retention[name] = value
    c['_report_retention'] = retention
    c.setdefault('model_url', None)
    if c['model_url'] is not None:
        endpoint(c['model_url'])
    c.setdefault('local_host', None)
    c.setdefault('optional_hosts', [])
    c.setdefault('dns_paths', [])
    c.setdefault('auth_paths', ['/var/log/auth.log'])
    c.setdefault('suspicious_domains', [])
    if c['local_host'] is not None and c['local_host'] not in inventory:
        raise ValueError('local_host must be in hosts')
    if not isinstance(c['optional_hosts'], list) or not set(c['optional_hosts']) <= set(inventory):
        raise ValueError('optional_hosts must be in hosts')
    for key in ('dns_paths', 'auth_paths'):
        if not isinstance(c[key], list) or not all(isinstance(p, str) and p.startswith('/') and '\x00' not in p for p in c[key]):
            raise ValueError('log paths must be absolute')
    if not isinstance(c['suspicious_domains'], list) or not all(isinstance(d, str) and re.fullmatch(r'[a-zA-Z0-9.-]{1,253}', d) for d in c['suspicious_domains']):
        raise ValueError('invalid suspicious_domains')
    c['suspicious_domains'] = sorted({d.lower().strip('.') for d in c['suspicious_domains']})
    c['level'] = validate_level(c.get('level', DEFAULT_LEVEL))
    if c.get('ntfy') is not None:
        c['ntfy'] = validate_ntfy(c['ntfy'])
    public = {k: v for k, v in c.items() if not k.startswith('_') and k not in
              ('feed', 'tiers', 'dns_api', 'level', 'model_url', 'ntfy', 'report_max_age_days', 'report_max_count')}
    public.setdefault('model', 'dolphin3:8b')
    c['_fingerprint'] = hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()
    return c


def finding(category, **fields):
    return dict(category=category, **fields)


def parse_nmap(xml, allowed, port_count=None, permitted_ports=None):
    root = ET.fromstring(xml)
    finished = root.find('runstats/finished')
    if finished is None or finished.get('exit') != 'success':
        raise ValueError('incomplete nmap run')
    snapshot = {}
    for host in root.findall('host'):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            raise ValueError('missing IPv4')
        ip = address.get('addr')
        if ip not in allowed or host.get('timedout') == 'true':
            raise ValueError('unexpected or timed-out host')
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            if port_count is not None:
                raise ValueError('unscanned host')
            continue
        ports = host.findall('ports/port')
        opened = sorted(int(p.get('portid')) for p in ports if p.find('state') is not None and p.find('state').get('state') == 'open')
        if port_count is not None:
            covered = len(ports) + sum(int(e.get('count')) for e in host.findall('ports/extraports'))
            if covered != port_count or any(p.get('protocol') != 'tcp' for p in ports):
                raise ValueError('partial port scan')
            if permitted_ports is not None and any(int(p.get('portid')) not in permitted_ports for p in ports):
                raise ValueError('unexpected port')
        if ip in snapshot:
            raise ValueError('duplicate host')
        snapshot[ip] = opened
    if port_count is not None and set(snapshot) != set(allowed):
        raise ValueError('missing scan targets')
    return snapshot


READ_COMMANDS = {('ip', '-j', 'addr'), ('ip', '-j', 'route'), ('tailscale', 'status', '--json')}


def command(args, timeout, input=None):
    if not args or (args[0] != 'nmap' and tuple(args) not in READ_COMMANDS):
        raise ValueError('command outside the subprocess allowlist')
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=True)
    return result.stdout


DISCOVERY = ['nmap', '-sn', '-n', '-PS22,80,443,445,3389,11434', '-oX', '-']
DEEP_SCRIPTS = 'ssh-auth-methods,http-auth,http-title,http-server-header,' + str(
    Path(__file__).resolve().with_name('coldguardian-model-list.nse'))
SCAN_ERRORS = (OSError, subprocess.SubprocessError, ValueError, ET.ParseError)
PRODUCT = re.compile(r'[A-Za-z0-9][A-Za-z0-9 ._/+()-]{0,63}')
SERVICE = re.compile(r'[a-z0-9][a-z0-9._/+-]{0,31}')
AUTH_METHOD = re.compile(r'[a-z0-9][a-z0-9-]{0,31}')


def service_findings(xml):
    results = []
    for host in ET.fromstring(xml).findall('host'):
        ip = host.find("address[@addrtype='ipv4']").get('addr')
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            service = port.find('service')
            service = {} if service is None else service.attrib
            fields = {'ip': ip, 'port': int(port.get('portid'))}
            if SERVICE.fullmatch(service.get('name', '')):
                fields['service'] = service['name']
            if PRODUCT.fullmatch(service.get('product', '')):
                fields['product'] = service['product']
            methods = [e.text for e in port.findall("script[@id='ssh-auth-methods']/table/elem")]
            if methods:
                fields['auth_methods'] = sorted({m for m in methods if m and AUTH_METHOD.fullmatch(m)})
            for script_id, field in (('banner', 'banner'), ('http-title', 'http_title')):
                script = port.find(f"script[@id='{script_id}']")
                if script is not None and (raw_text := script.findtext("elem[@key='title']") or script.get('output')):
                    fields[field] = raw_text
            results.append(finding('service', **fields))
    return results


def wireguard_selection(approved, known, deep):
    from .wizard import observed_wireguard

    observed = {
        network for network in observed_wireguard()
        if network.version == 4 and network.prefixlen >= MIN_PREFIX_LENGTH[4] and is_private_network(network)
    }
    targets = set()
    for scope in approved:
        for network in observed:
            if not network.overlaps(scope):
                continue
            narrow, wide = sorted((scope, network), key=lambda subnet: subnet.num_addresses)
            candidates = narrow.hosts() if deep else map(ipaddress.IPv4Address, known)
            targets.update(str(ip) for ip in candidates if usable_address(ip, narrow) and usable_address(ip, wide))
    missing = deep and any(not all(str(ip) in targets for ip in scope.hosts()) for scope in approved)
    return targets, missing


def target_input(targets, via_stdin):
    ordered = sorted(targets)
    if via_stdin:
        return ['-iL', '-'], {'input': ('\n'.join(ordered) + '\n').encode('ascii')}
    return ordered, {}


def scan(c, profile='deep', baseline=None, top_ports=None, *, observed_peers=()):
    if c['_lan'].version != 4 or any(':' in ip for ip in c['hosts'].values()):
        return {}, [finding('coverage', component='lan_discovery', error_type='UnsupportedAddressFamily')]
    names = {ip: host for host, ip in c['hosts'].items()}
    known = set(names) | set(baseline or {})
    check_snapshot_scope(c, known)
    lan = {str(ip) for ip in c['_lan'].hosts()}
    ordinary = set(names) | (known & lan)
    if profile == 'deep':
        known |= c['_tailscale_ipv4']
    peers = known & c['_tailscale_ipv4'] & set(observed_peers)
    wireguard_known = known - ordinary - peers
    wireguard = set()
    errors = []
    if c['_wireguard_ipv4'] and (profile == 'deep' or wireguard_known):
        try:
            wireguard, missing = wireguard_selection(c['_wireguard_ipv4'], wireguard_known, profile == 'deep')
            if missing:
                errors.append(finding('coverage', component='wireguard_discovery'))
        except (ValueError, TypeError, KeyError, AttributeError):
            errors.append(finding('coverage', component='wireguard_discovery'))
    candidates = ordinary | peers | wireguard
    via_stdin = bool(candidates - ordinary)
    discovered = {}
    if profile == 'deep' and c['_lan'].prefixlen != 32:
        try:
            discovered = parse_nmap(command(DISCOVERY + [str(c['_lan'])], 90), lan)
        except SCAN_ERRORS as error:
            return {}, errors + [finding('coverage', component='lan_discovery', error_type=type(error).__name__)]
    try:
        discovery_args, discovery_input = target_input(candidates, via_stdin)
        reachable = parse_nmap(command(DISCOVERY + discovery_args, 90, **discovery_input), candidates)
    except SCAN_ERRORS as error:
        return {}, errors + [finding('coverage', component='host_discovery', error_type=type(error).__name__)]
    targets = set(discovered) | set(reachable)
    errors.extend(finding('coverage', component='host_offline', **({'host': names[ip]} if ip in names else {}), ip=ip, optional=names.get(ip) in c['optional_hosts']) for ip in sorted(known - targets))
    if not targets:
        return {}, errors
    if profile == 'deep':
        ports = ['--top-ports', str(top_ports)] if top_ports else ['-p', c['ports']]
        args = ['-sV', '--script', DEEP_SCRIPTS, *ports]
        timeout, port_count, permitted = 3600, top_ports or c['_port_count'], None if top_ports else c['_ports']
    else:
        baseline_ports = {p for opened in (baseline or {}).values() for p in opened}
        if baseline is not None and not baseline_ports:
            return {ip: [] for ip in sorted(targets)}, errors
        spec = ','.join(map(str, sorted(baseline_ports))) if baseline_ports else c['ports']
        args, timeout, port_count, permitted = ['-p', spec], 1200, len(baseline_ports) or c['_port_count'], baseline_ports or c['_ports']
    try:
        target_args, targets_input = target_input(targets, via_stdin)
        xml = command(['nmap', '-sT', '-Pn', '-n', *args, '--max-rate', '5000', '--max-retries', '1', '-oX', '-', *target_args], timeout, **targets_input)
        snapshot = parse_nmap(xml, targets, port_count, permitted)
        if profile == 'deep':
            errors.extend(service_findings(xml))
            for item in rules.check(xml):
                for field, pattern in (('service', SERVICE), ('product', PRODUCT)):
                    if not pattern.fullmatch(item[field]):
                        item.pop(field)
                errors.append(item)
        return snapshot, errors
    except SCAN_ERRORS as error:
        return {}, errors + [finding('coverage', component='tcp_scan', error_type=type(error).__name__)]
