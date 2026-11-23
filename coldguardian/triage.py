from collections import Counter
import ipaddress
import time

from . import model


RISK_PORTS = frozenset({21, 23, 139, 445, 2375, 3389, 5900, 6379, 9200, 11434, 27017})
HOUSEHOLD_PORTS = frozenset({80, 443, 5357, 8008, 8009, 62078})
PUBLIC_EXPOSURES = {'upnp_mapping', 'tailscale_funnel'}
HARD_CATEGORIES = PUBLIC_EXPOSURES | {'risky_service', 'dns_feed_match', 'dns_suffix', 'link_feed_hit', 'login_burst'}


def server_addresses(tiers, hosts):
    if (not isinstance(tiers, dict) or set(tiers) != {'servers', 'household'}
            or tiers['household'] != 'lan' or not isinstance(tiers['servers'], list)
            or not all(isinstance(name, str) and name in hosts for name in tiers['servers'])):
        raise ValueError('tiers requires servers (inventory names) and household set to lan')
    return {hosts[name] for name in tiers['servers']}


def classify(c, findings, snapshot, macs, approved, *, complete):
    if 'tiers' not in c:
        for item in findings:
            if item['category'] in PUBLIC_EXPOSURES:
                item['delivery_class'] = 'hard_page'
        return
    servers = c['_servers']
    new = {f['ip'] for f in findings if f['category'] == 'new_device'}
    hard_hosts = {f.get('client_ip') or f.get('ip') for f in findings if f['category'] in HARD_CATEGORIES}
    hard_hosts.update(ip for ip in new if RISK_PORTS.intersection(snapshot.get(ip, ())))
    risky_new = new & hard_hosts
    before, after = Counter(approved.values()), Counter(macs.values())
    moved = {ip for ip, mac in approved.items() if ip not in snapshot and before[mac] == after[mac] == 1}
    moved_macs = {approved[ip] for ip in moved}
    verdicts = {}
    deadline = time.monotonic() + 3
    for item in findings:
        category = item['category']
        ip = item.get('ip')
        if (category in HARD_CATEGORIES
                or category in {'new_ports', 'baseline_drift', 'persistence_drift'} and ip in servers
                or category in {'new_device', 'new_ports'} and ip in risky_new):
            if category == 'new_device' and (risky_ports := RISK_PORTS.intersection(snapshot.get(ip, ()))):
                item['ports'] = sorted(risky_ports)
            item['delivery_class'] = 'hard_page'
            continue
        if (category == 'coverage' and item.get('component') == 'host_offline'
                and ip in moved and ip not in servers and complete):
            item['delivery_class'] = 'digest'
        if category not in {'new_device', 'new_ports'} or ip not in new or ip in servers:
            continue
        if not complete or ip not in snapshot or ipaddress.ip_address(ip) not in c['_lan']:
            continue
        ports = tuple(snapshot[ip])
        mac = macs.get(ip)
        if not ports or (mac and (int(mac[:2], 16) & 2 or mac in moved_macs)):
            item['delivery_class'] = 'digest'
        elif c['model_url'] and len(ports) == 1 and ports[0] in HOUSEHOLD_PORTS:
            if ports not in verdicts:
                verdicts[ports] = model.device_triage(c['model_url'], ports, deadline)
            verdict = verdicts[ports]
            if verdict:
                item['triage_label'], item['triage_reason'] = verdict
                if item['triage_label'] in {'review_later', 'likely_household'}:
                    item['delivery_class'] = 'digest'
