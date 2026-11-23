from collections import Counter
import re

from .scan import finding, valid_mac
from .scope import check_snapshot_scope


def differences(snapshot, baseline, *, compare_missing_ports=True):
    results = []
    for ip, ports in sorted(snapshot.items()):
        if ip not in baseline:
            results.append(finding('new_device', ip=ip))
        added = sorted(set(ports) - set(baseline.get(ip, [])))
        if added:
            results.append(finding('new_ports', ip=ip, ports=added))
        if compare_missing_ports:
            missing = sorted(set(baseline.get(ip, [])) - set(ports))
            if missing:
                results.append(finding('baseline_drift', ip=ip, ports=missing))
    return results


def compare_devices(snapshot, approved, macs, risky_ips, *, compare_missing_ports=True):
    baseline = dict(approved['hosts'])
    approved_macs = approved.get('macs', {})
    before_counts = Counter(approved_macs.values())
    after_counts = Counter(macs.values())
    missing_by_mac = {
        mac: ip for ip, mac in approved_macs.items()
        if ip not in snapshot and before_counts[mac] == 1
    }
    for ip, mac in macs.items():
        if ip in baseline:
            old = approved_macs.get(ip)
            if old is None or old == mac:
                continue
            if (int(old[:2], 16) & 2 and int(mac[:2], 16) & 2
                    and before_counts[old] == after_counts[mac] == 1
                    and mac not in before_counts and old not in after_counts
                    and ip not in risky_ips and snapshot[ip] == baseline[ip]):
                continue
            del baseline[ip]
        elif ip not in risky_ips and after_counts[mac] == 1 and mac in missing_by_mac:
            baseline[ip] = baseline[missing_by_mac[mac]]
    return differences(snapshot, baseline, compare_missing_ports=compare_missing_ports)


def approved_snapshot(state, c):
    snapshot = state.get('snapshot', {})
    if snapshot.get('fingerprint') != c['_fingerprint'] or snapshot.get('complete') is not True or not snapshot.get('hosts'):
        raise ValueError('no complete matching prior snapshot')
    hosts = snapshot['hosts']
    if not isinstance(hosts, dict):
        raise ValueError('invalid snapshot scope')
    check_snapshot_scope(c, hosts.keys())
    if any(not isinstance(ports, list) or any(type(p) is not int or p not in c['_ports'] for p in ports) for ports in hosts.values()):
        raise ValueError('invalid snapshot ports')
    approved = {'fingerprint': c['_fingerprint'], 'hosts': hosts, 'offline_inventory': sorted(set(c['hosts'].values()) - set(hosts))}
    if 'approvals' in snapshot:
        approvals = snapshot['approvals']
        if not isinstance(approvals, list) or any(
            not isinstance(entry, dict) or not isinstance(entry.get('finding'), dict)
            for entry in approvals
        ):
            raise ValueError('invalid baseline approvals')
        approved['approvals'] = approvals
    if 'persistence' in snapshot:
        hashes = snapshot['persistence']
        if not isinstance(hashes, dict) or not all(
            isinstance(path, str) and path.startswith('/') and isinstance(digest, str)
            and re.fullmatch('[0-9a-f]{64}', digest) for path, digest in hashes.items()
        ):
            raise ValueError('invalid persistence baseline')
        approved['persistence'] = hashes
    if 'macs' in snapshot:
        macs = snapshot['macs']
        if not isinstance(macs, dict) or any(ip not in hosts or not valid_mac(mac) for ip, mac in macs.items()):
            raise ValueError('invalid snapshot MAC addresses')
        approved['macs'] = macs
    return approved
