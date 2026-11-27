"""Read-only, inventory-bounded network monitoring."""
import argparse
import collections
from contextlib import contextmanager, nullcontext, redirect_stdout, suppress
from datetime import datetime, timedelta, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

from . import dnswatch, exposure, feeds, hostwatch, model, notify, triage, wizard
from .baseline import approved_snapshot, compare_devices, differences
from .endpoints import validate_ntfy
from .levels import DEFAULT_LEVEL, LEVELS
from .lookups import LookupContext
from .report import (
    ARCHIVE_STAMP, JournalCorruption, atomic_json, journal_rows, load_json, report, report_text, safe_finding,
    saved_finding, scan_document,
)
from .scan import config, finding, lan_macs, scan, valid_ip
from .scope import ScopeError, tailscale_address


READ_LIMIT = 1024 * 1024
MAX_CHUNKS = 32
COLLECT_SECONDS = 60
LOGIN_FAILURES = 5
LOGIN_WINDOW = 60
AUTH_FAILURE = re.compile(r'Failed (?:password|publickey)|authentication failure|Invalid user', re.I)
SSH_FAILURE = re.compile(
    r'^(?:\S+|[A-Z][a-z]{2} +\d{1,2} \d\d:\d\d:\d\d) \S+ '
    r'sshd(?:-session)?\[\d+\]: Failed (?:password|publickey) for .+ from (\S+) port \d+\b'
)


def auth_client(line):
    match = re.search(r'\bfrom\s+(\S+)|\brhost=(\S+)', line)
    return valid_ip(match[1] or match[2]) if match else None


def auth_time(line, now):
    try:
        return datetime.fromisoformat(line.split(maxsplit=1)[0]).timestamp()
    except ValueError:
        for year in (now.year, now.year - 1):
            try:
                stamp = datetime.strptime(f'{year} {line[:15]}', '%Y %b %d %H:%M:%S')
            except ValueError:
                continue
            if stamp <= now + timedelta(days=1):
                return stamp.timestamp()
    return None


def burst_count(times):
    start, largest = 0, 0
    times.sort()
    for end, stamp in enumerate(times):
        while stamp - times[start] > LOGIN_WINDOW:
            start += 1
        largest = max(largest, end - start + 1)
    return largest


def dns_category(domain, suffixes, feed_domains=frozenset()):
    if feed_domains and feeds.domain_key(domain) in feed_domains:
        return 'dns_feed_match'
    domain = domain.lower().rstrip('.')
    if any(domain == s or domain.endswith('.' + s) for s in suffixes):
        return 'dns_suffix'
    for label in domain.split('.'):
        if len(label) >= 40:
            return 'dns_long_label'
        if len(label) >= 24:
            entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in collections.Counter(label).values())
            if entropy >= 4:
                return 'dns_entropy'
    return None


def summarize_logs(data, kind, suffixes, feed_domains=frozenset(), observations=None):
    counts = collections.Counter()
    invalid = 0
    for line in data.splitlines():
        if not line.strip():
            continue
        if kind == 'dns':
            try:
                row = json.loads(line)
                domain, client = row['QH'], valid_ip(row.get('IP'))
                if not isinstance(domain, str) or not client:
                    raise ValueError('invalid DNS row')
            except (ValueError, TypeError, KeyError):
                row = None
                match = re.search(r'query\[[^\]]+\]\s+(\S+)\s+from\s+(\S+)', line)
                if not match:
                    invalid += 1
                    continue
                domain, client = match[1], valid_ip(match[2])
                if not client:
                    invalid += 1
                    continue
            if observations is not None:
                if row is None:
                    stamp = auth_time(line, datetime.now())
                else:
                    try:
                        stamp = datetime.fromisoformat(row['T'].replace('Z', '+00:00')).timestamp()
                    except (ValueError, KeyError, AttributeError, TypeError, OverflowError, OSError):
                        stamp = None
                if stamp is not None:
                    observations.append((stamp, client, domain))
            category = dns_category(domain, suffixes, feed_domains)
            if category:
                counts[(category, client)] += 1
        elif AUTH_FAILURE.search(line):
            counts[('auth_failed', auth_client(line))] += 1
    results = [finding(cat, count=count, **({'client_ip': ip} if ip else {})) for (cat, ip), count in sorted(counts.items(), key=lambda item: str(item[0]))]
    if invalid:
        results.append(finding('coverage', component='dns_parse', count=invalid))
    return results


def open_log(path):
    return open(path, 'rb', opener=lambda name, flags: os.open(name, flags | os.O_NONBLOCK))


def read_log_chunk(log, start, discard_partial=False):
    limit = READ_LIMIT
    if discard_partial and start:
        log.seek(start - 1)
        if log.read(1) != b'\n':
            log.readline(READ_LIMIT)
        limit -= log.tell() - start
        start = log.tell()
    else:
        log.seek(start)
    chunk = log.read(limit)
    end = chunk.rfind(b'\n') + 1
    return chunk[:end].decode('utf-8', 'replace'), start + end


def collect_auth(log, info, checkpoint, deadline):
    identity = f'{info.st_dev}:{info.st_ino}'
    issues = set()
    if checkpoint is not None:
        offset = checkpoint['offset']
        if type(offset) is not int or offset < 0 or not isinstance(checkpoint['identity'], str):
            raise ValueError('invalid authentication log checkpoint')
        if checkpoint['identity'] != identity or offset > info.st_size:
            offset = 0
            issues.add('rotated')
    else:
        offset = max(0, info.st_size - READ_LIMIT)
        if offset:
            issues.add('history_skipped')

    counts = collections.Counter()
    failed_at = collections.defaultdict(list)
    now = datetime.now()
    for index in range(MAX_CHUNKS):
        if time.monotonic() >= deadline:
            break
        data, offset = read_log_chunk(log, offset, index == 0 and 'history_skipped' in issues)
        checkpoint = {'identity': identity, 'offset': offset}
        for line in data.splitlines():
            if not AUTH_FAILURE.search(line):
                continue
            counts[auth_client(line)] += 1
            match = SSH_FAILURE.search(line)
            if match and (ip := valid_ip(match[1])) and (stamp := auth_time(line, now)) is not None:
                failed_at[ip].append(stamp)
        if offset >= info.st_size or not data:
            break
    if offset < info.st_size:
        issues.add('backlog')
    findings = [
        finding('auth_failed', count=count, **({'client_ip': ip} if ip else {}))
        for ip, count in counts.items()
    ]
    for ip, times in sorted(failed_at.items()):
        count = burst_count(times)
        if count >= LOGIN_FAILURES:
            findings.append(finding('login_burst', client_ip=ip, count=count, window_seconds=LOGIN_WINDOW))
    return checkpoint, findings, issues


def cached_feed_domains(c):
    _, domains, warning = feeds.read_cache(Path(c['output_dir']), c.get('feed'))
    return domains, warning


def collect(c, checkpoints, cached_domains=None, *, excluded=()):
    host = c['local_host']
    pending = {key: value for key, value in checkpoints.items() if key.split(':', 2)[:2] == [host, 'auth']}
    findings = []
    feed_domains, warning = cached_feed_domains(c) if cached_domains is None else cached_domains
    if c.get('feed') is not None and warning:
        findings.append(finding('coverage', component=warning))
    observations = [] if 'tiers' in c or 'dns_api' in c else None
    if 'dns_api' in c:
        source = c['dns_api']
        address = c['hosts'][source['host']]
        key = f"dns:{source['provider']}:{address}:{source.get('port', 443)}"
        previous = checkpoints.get(key, {})
        if address in excluded:
            rows, pending[key], issues = [], previous, {'deep_excluded'}
        else:
            rows, pending[key], issues = dnswatch.api_queries(source, address, previous, int(time.time()))
        observations.extend(rows)
        counts = collections.Counter()
        for _, client, domain in rows:
            category = dns_category(domain, c['suspicious_domains'], feed_domains)
            if category:
                counts[(category, client)] += 1
        fields = {'kind': 'dns', 'host': source['host']}
        findings.extend(finding(cat, client_ip=client, count=count, **fields) for (cat, client), count in counts.items())
        findings.extend(finding('coverage', component=issue, **fields) for issue in sorted(issues))
        findings.append(finding('source_summary', status='partial' if issues else 'ok', **fields))
    deadline = time.monotonic() + COLLECT_SECONDS
    paths = [('auth', p) for p in c['auth_paths']] + [('dns', p) for p in c['dns_paths']]
    for kind, path in (paths if host is not None else ()):
        if time.monotonic() >= deadline:
            findings.append(finding('coverage', component='log_backlog', host=host, kind=kind))
            findings.append(finding('source_summary', host=host, kind=kind, status='partial'))
            continue
        try:
            with open_log(path) as log:
                info = os.fstat(log.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError('log path must be a regular file')
                if kind == 'auth':
                    key = host + ':auth:' + path
                    checkpoint, rows, issues = collect_auth(log, info, pending.get(key), deadline)
                    if checkpoint is not None:
                        pending[key] = checkpoint
                else:
                    start = max(0, info.st_size - READ_LIMIT)
                    data, end = read_log_chunk(log, start, discard_partial=True)
                    rows = summarize_logs(data, 'dns', c['suspicious_domains'], feed_domains, observations)
                    issues = {'history_skipped'} if start else set()
                    if end < info.st_size:
                        issues.add('backlog')
            findings.extend(dict(row, host=host, kind=kind) for row in rows)
        except (OSError, ValueError, TypeError, KeyError):
            issues = {'read'}
        findings.append(finding('source_summary', host=host, kind=kind, status='partial' if issues else 'ok'))
        findings.extend(finding('coverage', component='log_' + issue, host=host, kind=kind) for issue in sorted(issues))
    if observations is not None:
        bursts, pending['dns_seen'] = dnswatch.first_seen_bursts(observations, checkpoints.get('dns_seen', {}), time.time())
        findings.extend(finding('dns_first_seen_burst', client_ip=ip, count=count, window_seconds=60)
                        for ip, count in bursts.items())
    return pending, findings


def explain_finding(url, key, item, lookup=None, *, advisory_log=None):
    if url is None or item['category'] in (
        'source_summary', 'scan_summary', 'baseline_approved', 'baseline_enrolled', 'service',
    ):
        return None

    def timed_out(*_):
        raise TimeoutError('model deadline')

    previous_handler = signal.signal(signal.SIGALRM, timed_out)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, model.TIMEOUT)
    try:
        return model.explain(url, {key: item}, lookup=lookup, advisory_log=advisory_log)
    except OSError:
        return None
    finally:
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        signal.signal(signal.SIGALRM, previous_handler)


def peer_changes(c, state):
    if 'tailscale_peers' not in c:
        return None, []
    previous = state.get('tailscale_peers', c['tailscale_peers'])
    findings = []
    try:
        if not isinstance(previous, list):
            raise ValueError('invalid peer snapshot')
        previous = {str(tailscale_address(ip, 'saved Tailscale peer')) for ip in previous}
    except ValueError:
        findings.append(finding('coverage', component='state_read'))
        previous = None
    try:
        observed = wizard.observed_peers(optional=not previous and not c['tailscale_peers'])
    except (ValueError, TypeError, AttributeError):
        return None, findings + [finding('coverage', component='tailscale_status')]
    if previous is None:
        return observed, findings
    current = set(observed)
    return observed, [
        finding('peer_change', ip=ip, change=change)
        for change, addresses in (('added', current - previous), ('removed', previous - current))
        for ip in sorted(addresses)
    ]


@contextmanager
def output_lock(outdir):
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if outdir.is_symlink():
        raise ValueError('output directory cannot be a symlink')
    os.chmod(outdir, 0o700)
    lockfd = os.open(outdir / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, 'w') as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
        else:
            yield True


def run(c, approve=False, profile='deep', top_ports=None, *, confirm_baseline=None,
        scan_command=False, json_output=False, setup_inventory=False):
    outdir = Path(c['output_dir'])
    with output_lock(outdir) as locked:
        if not locked:
            result = [finding('coverage', component='overlapping_run')]
            print(json.dumps(scan_document(result, profile, c['level'])) if json_output
                  else '# Coldguardian\n\n- {"category":"coverage","component":"overlapping_run"}')
            return 2
        findings = []
        retention = c['_report_retention']
        try:
            state = load_json(outdir / 'state.json', {})
            if not isinstance(state, dict) or not isinstance(state.get('checkpoints', {}), dict):
                raise ValueError('invalid state')
        except (OSError, ValueError):
            state = {}
            findings.append(finding('coverage', component='state_read'))
        if approve:
            for _ in journal_rows(outdir):
                pass
            try:
                baseline = approved_snapshot(state, c)
                if not c.get('host_watch'):
                    baseline.pop('persistence', None)
                with suppress(ValueError, TypeError, AttributeError):
                    existing = approved_snapshot({'snapshot': dict(load_json(outdir / 'baseline.json'), complete=True)}, c)
                    if 'persistence' in existing and (
                        'persistence' not in baseline or state['snapshot'].get('persistence_complete') is False
                    ):
                        baseline['persistence'] = existing['persistence'] | baseline.get('persistence', {})
                    if 'approvals' in existing:
                        baseline['approvals'] = existing['approvals']
                atomic_json(outdir / 'baseline.json', baseline)
                report(outdir, [finding('baseline_approved')], pinned=state.get('report_timestamp'), **retention)
                return 0
            except (OSError, ValueError, TypeError, KeyError):
                report(outdir, [finding('coverage', component='baseline_approval')],
                       pinned=state.get('report_timestamp'), **retention)
                return 2
        approved, baseline_error = None, False
        try:
            baseline = load_json(outdir / 'baseline.json')
            if baseline is not None and baseline['fingerprint'] == c['_fingerprint']:
                approved = approved_snapshot({'snapshot': dict(baseline, complete=True)}, c)
        except (OSError, ValueError, TypeError, KeyError):
            baseline_error = True
        if confirm_baseline is not None:
            if baseline_error or (os.path.lexists(outdir / 'baseline.json') and approved is None):
                print('Restore the matching saved configuration and baseline before rerunning coldguardian setup.', file=sys.stderr)
                return 2
            if findings:
                print('Repair or restore state.json before rerunning coldguardian setup.', file=sys.stderr)
                return 2
            if approved is not None:
                print('Keeping the approved baseline.')
                return 0
        if profile == 'deep':
            if c['_port_count'] < 65535:
                top_ports = None
            elif top_ports is None:
                top_ports = LEVELS[c['level']].deep_top_ports
        peers, peer_findings = (
            peer_changes(c, state) if confirm_baseline is None else (c.get('tailscale_peers'), [])
        )
        approved_hosts = approved['hosts'] if approved is not None else None
        snapshot, scan_findings = scan(c, profile, approved_hosts, top_ports, observed_peers=peers or ())
        macs = lan_macs(snapshot, c['_lan']) if snapshot else {}
        findings.extend(scan_findings)
        network_complete = not any(f['category'] == 'coverage' and f.get('component') != 'host_offline'
                                   and not f.get('optional') for f in scan_findings)
        if baseline_error:
            findings.append(finding('coverage', component='baseline_read'))
        elif baseline is None:
            findings.append(finding('baseline_missing'))
            findings.extend(finding('observed_host', ip=ip, ports=ports) for ip, ports in sorted(snapshot.items()))
        elif approved is None:
            findings.append(finding('baseline_mismatch'))
        elif 'tiers' in c or c['level'] == 'high' or not network_complete:
            findings.extend(differences(snapshot, approved_hosts, compare_missing_ports=top_ports is None))
            if 'tiers' in c:
                old_macs = approved.get('macs', {})
                findings.extend(finding('new_device', ip=ip) for ip, mac in macs.items()
                                if ip in old_macs and mac != old_macs[ip])
        else:
            risky_ips = {f['ip'] for f in scan_findings if f['category'] == 'risky_service'}
            findings.extend(compare_devices(snapshot, approved, macs, risky_ips, compare_missing_ports=top_ports is None))
        findings.extend(peer_findings)
        excluded = c.get('deep_exclusions', ()) if profile == 'deep' else ()
        exposure_findings, exposure_status = exposure.collect(c, excluded=excluded)
        findings.extend(exposure_findings)
        network_complete = network_complete and 'incomplete' not in exposure_status.values()
        if c.get('host_watch'):
            host_findings, hashes, watch_status = hostwatch.collect(c, approved)
            findings.extend(host_findings)
        cached_domains = cached_feed_domains(c)
        checkpoints, log_findings = collect(c, state.get('checkpoints', {}), cached_domains, excluded=excluded)
        findings.extend(log_findings)
        findings.insert(0, finding('scan_summary', host_count=len(snapshot), network_complete=network_complete, log_sources=sum(f['category'] == 'source_summary' for f in log_findings), log_coverage_complete=not any(f['category'] == 'coverage' for f in log_findings)))
        gaps = {f.get('component') for f in findings if f['category'] == 'coverage' and not f.get('optional')}
        if confirm_baseline is None:
            dns_complete = not any(f['category'] == 'coverage' for f in log_findings)
            triage.classify(c, findings, snapshot, macs, (approved or {}).get('macs', {}),
                            complete=network_complete and dns_complete and profile == 'deep')
        approvals = [entry['finding'] for entry in (approved or {}).get('approvals', [])]

        last_success = scan_timestamps(c, state)
        if gaps <= hostwatch.GAPS.keys() and approved is not None:
            last_success[profile] = int(time.time())

        def notify_pending(stamp):
            heartbeat = None
            if 'tiers' in c:
                health = freshness(c, last_success)
                if any(v['status'] not in ('fresh', 'unscheduled') for v in health.values()) or gaps:
                    heartbeat = 'Monitoring is incomplete. Check coldguardian status --json and the local report.'
                elif any(f.get('delivery_class') == 'hard_page' for f in findings):
                    heartbeat = 'Monitoring is current. Threat findings are in the local report.'
                else:
                    heartbeat = 'Monitoring is current. Review the local report for this week’s observations.'
            return notify.deliver_notification(
                state, findings, lambda: atomic_json(outdir / 'state.json', state),
                level=c.get('level', DEFAULT_LEVEL), target=c.get('ntfy', notify.LEGACY_TARGET),
                approvals=approvals, stamp=stamp, heartbeat=heartbeat,
            )

        def save_scan(stamp):
            try:
                previous = approved_snapshot(state, c)['hosts']
            except (AttributeError, ValueError, TypeError, KeyError):
                previous = {}
            state.update(last_success=last_success, checkpoints=checkpoints, snapshot={'fingerprint': c['_fingerprint'], 'complete': network_complete, 'hosts': snapshot},
                         report_timestamp=stamp, previous_hosts=previous)
            if c.get('host_watch'):
                state['snapshot']['host_watch'] = watch_status
                state['snapshot']['persistence'] = hashes
                state['snapshot']['persistence_complete'] = 'host_persistence' not in gaps
            if macs:
                state['snapshot']['macs'] = macs
            if exposure_status:
                state['exposure'] = {k: {'config': c[k], 'status': v} for k, v in exposure_status.items()}
            else:
                state.pop('exposure', None)
            if peers is not None:
                state['tailscale_peers'] = peers
            atomic_json(outdir / 'state.json', state)

        record = report(outdir, findings, notify=notify_pending if confirm_baseline is None else None,
                        emit=not json_output, pinned=state.get('report_timestamp'), save_scan=save_scan,
                        **retention)
        if confirm_baseline is not None:
            try:
                baseline = approved_snapshot(state, c)
            except ValueError:
                print('The scan did not produce a complete baseline. Review the report and rerun coldguardian setup.', file=sys.stderr)
                return 2
            if not confirm_baseline():
                print('Baseline left unapproved. Rerun coldguardian setup to resume.')
                return 2
            atomic_json(outdir / 'baseline.json', baseline)
            print(f"Approved {outdir / 'baseline.json'}")
            return 0
        if setup_inventory:
            inventory = [f for f in findings if f.get('scope') != hostwatch.SCOPE]
            return scan_document(inventory, profile, c['level'])['exit_code']
        if scan_command:
            document = scan_document(findings, profile, c['level'], record)
            if json_output:
                print(json.dumps(document, sort_keys=True))
            return document['exit_code']
        return 1 if any(f['category'] not in ('scan_summary', 'source_summary', 'host_listener', 'service') for f in findings) else 0


def approve_finding(c, finding_id, reason):
    if not reason or not reason.strip():
        raise ValueError('A nonempty --reason is required.')
    outdir = Path(c['output_dir'])
    with output_lock(outdir) as locked:
        if not locked:
            raise ValueError('Another monitoring run is active.')
        row, key, item = saved_finding(outdir, finding_id)
        state = load_json(outdir / 'state.json', {})
        if (row['timestamp'] != state.get('report_timestamp')
                or state['snapshot']['fingerprint'] != c['_fingerprint']):
            raise ValueError('Approve findings from the latest scan for this configuration.')
        if item.get('delivery_class') == 'hard_page' and ('tiers' in c or item['category'] in triage.PUBLIC_EXPOSURES):
            raise ValueError('A hard-threat finding always pages and cannot be approved.')
        item = safe_finding(item)
        if item['category'] in ('coverage', *notify.PAGE_NOTES) or not notify.notification_items([item]):
            raise ValueError('This finding cannot be approved.')
        path = outdir / 'baseline.json'
        baseline = approved_snapshot({'snapshot': dict(load_json(path, {}), complete=True)}, c)
        approvals = baseline.setdefault('approvals', [])
        if any(entry['finding'] == item for entry in approvals):
            return 1, {'status': 'already_approved'}
        approval = {
            'finding_id': f"{row['timestamp']}:{key}",
            'finding': item,
            'reason': reason,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        approvals.append(approval)
        atomic_json(path, baseline)
        return 0, {'status': 'approved', 'approval': approval}


def explain_saved_finding(c, finding_id):
    outdir = Path(c['output_dir'])
    row, key, item = saved_finding(outdir, finding_id)
    lookup = None
    if c['model_url']:
        state = load_json(outdir / 'state.json', {})
        snapshot = state.get('snapshot', {})
        if (state.get('report_timestamp') == row['timestamp']
                and snapshot.get('fingerprint') == c['_fingerprint']):
            baseline = load_json(outdir / 'baseline.json') or {}
            approved = baseline.get('hosts', {}) if baseline.get('fingerprint') == c['_fingerprint'] else {}
            lookup = LookupContext(c, approved, state.get('previous_hosts', {}), snapshot['hosts'],
                                   row['findings'], *cached_feed_domains(c))
    explanation = explain_finding(c['model_url'], key, item, lookup, advisory_log=c.get('advisory_log'))
    if explanation is None:
        raise ValueError('Local model explanation is unavailable for this finding.')
    code = scan_document([item], None, c['level'])['exit_code']
    return code, {'status': ('clean', 'bad', 'incomplete')[code], 'explanation': explanation}


def finding_command(args):
    command = args.feed_command
    try:
        if not args.config:
            raise ValueError('Missing configuration.')
        c = config(json.loads(Path(args.config).read_text()))
        if command == 'approve':
            code, result = approve_finding(c, args.finding_id, args.reason)
        else:
            code, result = explain_saved_finding(c, args.finding_id)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        code, result = 2, {'status': 'failed', 'error_type': type(error).__name__}
        print(error, file=sys.stderr)
    if args.json:
        print(json.dumps(dict(result, command=command, finding_id=args.finding_id, exit_code=code)))
    elif 'explanation' in result:
        explanation = result['explanation']
        print(f"{explanation['label']}: {explanation['reason']}")
        if explanation['missing']:
            print('Missing evidence: ' + ', '.join(explanation['missing']))
    elif code != 2:
        print('Finding approved.' if code == 0 else 'Finding was already approved.')
    return code


def management_command(args):
    command = args.feed_command
    with redirect_stdout(sys.stderr) if args.json else nullcontext():
        if command == 'feeds':
            command = 'feeds update'
            code = feeds.run_command(args)
            status = 'ok' if code == 0 else 'failed'
        else:
            try:
                if command == 'setup':
                    code, status = wizard.setup(run, json_output=args.json, yes=args.yes)
                else:
                    code, status = wizard.uninstall(), 'ok'
            except (EOFError, KeyboardInterrupt):
                print('Rerun coldguardian setup to resume. For unattended checks, use coldguardian status --json.'
                      if command == 'setup' else 'Canceled.', file=sys.stderr)
                code, status = 2, 'canceled'
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                print(error, file=sys.stderr)
                code, status = 2, 'failed'
    if args.json:
        outcome = dict(command=command, status=status, exit_code=code)
        if command == 'setup':
            outcome['schema_version'] = 1
        print(json.dumps(outcome))
    return code


def scan_timestamps(c, state):
    snapshot, history = state.get('snapshot'), state.get('last_success')
    if isinstance(snapshot, dict) and snapshot.get('fingerprint') == c['_fingerprint'] and isinstance(history, dict):
        return dict(history)
    return {}


def freshness(c, last_success):
    day = 86400
    limits = {'quick': 9 * 3600 if c['level'] == 'high' else 36 * 3600,
              'deep': {'low': None, 'medium': 8 * day, 'high': 36 * 3600}[c['level']],
              'feeds': feeds.MAX_AGE if c.get('feed') else None}
    stamps = dict(last_success)
    if c.get('feed'):
        _, _, _, stamps['feeds'] = feeds.cached_indicators(Path(c['output_dir']), c['feed'])
    now = time.time()
    result = {}
    for key, limit in limits.items():
        stamp = stamps.get(key)
        valid = type(stamp) is int and 0 <= stamp <= now
        status = 'unscheduled' if limit is None else 'missing'
        if limit is not None and valid:
            status = 'fresh' if now - stamp <= limit else 'stale'
        result[key] = {'last_success': stamp if valid else None, 'status': status}
    return result


def status_command(args):
    path = Path(args.config) if args.config else wizard.setup_config()
    details = {}
    try:
        settings = json.loads(path.read_text())
        if not isinstance(settings, dict):
            raise ValueError('configuration must be an object')
        c = config(settings)
    except (OSError, TypeError, ValueError, RecursionError):
        code, status = 2, 'failed'
        print('Could not read or validate the Coldguardian configuration.', file=sys.stderr)
    else:
        code, status = 0, 'ok'
        sources = [key for key in exposure.STATUS if c.get(key)]
        if args.json or sources or c.get('host_watch'):
            try:
                state = load_json(Path(c['output_dir']) / 'state.json')
            except (OSError, ValueError, RecursionError):
                state = {}
            if state is not None or any(k in c for k in ('tiers', 'dns_api', 'feed')):
                stamps = scan_timestamps(c, state) if isinstance(state, dict) else {}
                details['freshness'] = freshness(c, stamps)
            if c.get('host_watch'):
                snapshot = state.get('snapshot') if isinstance(state, dict) else None
                observed = (isinstance(snapshot, dict) and snapshot.get('fingerprint') == c['_fingerprint']
                            and snapshot.get('host_watch') == 'ok')
                details['host_watch'] = {'scope': hostwatch.SCOPE, 'status': 'ok' if observed else 'incomplete'}
                if not observed:
                    code, status = 2, 'incomplete'
                if not args.json:
                    print(f"Host watch ({hostwatch.SCOPE}): {details['host_watch']['status']}.")
            if sources:
                saved = state.get('exposure') if isinstance(state, dict) else None
                coverage = {}
                for key in sources:
                    entry = saved.get(key) if isinstance(saved, dict) else None
                    result = entry.get('status') if isinstance(entry, dict) and entry.get('config') == c[key] else None
                    if result not in ('clear', 'exposed'):
                        result = 'incomplete'
                        code, status = 2, 'incomplete'
                    coverage[key] = {'status': result, 'message': exposure.STATUS[key][result]}
                details['exposure'] = coverage
                if not args.json:
                    for entry in coverage.values():
                        print(entry['message'])
        if not args.json:
            print('Coldguardian configuration is valid.')
    if args.json:
        print(json.dumps(dict(command='status', status=status, exit_code=code, **details)))
    return code


DEMO_FINDINGS = (
    finding('scan_summary', host_count=4, network_complete=True, log_sources=0, log_coverage_complete=True),
    finding('new_device', ip='192.168.1.23'),
    finding('new_ports', ip='192.168.1.23', ports=[22, 8080]),
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config')
    commands = parser.add_subparsers(dest='feed_command')
    setup = commands.add_parser('setup', help='Configure Coldguardian and approve the first scan')
    setup.add_argument('--json', action='store_true', help='Print the outcome as JSON')
    setup.add_argument('--yes', action='store_true',
                       help='Accept the detected scope, Medium level, no model, no phone alerts and the first baseline without prompting')
    uninstall = commands.add_parser('uninstall', help='Remove setup-managed units, configuration, and state')
    uninstall.add_argument('--json', action='store_true', help='Print the outcome as JSON')
    commands.add_parser('demo', help='Print a sample report without scanning or writing files')
    status = commands.add_parser('status', help='Check local configuration without scanning')
    status.add_argument('--config', default=argparse.SUPPRESS)
    status.add_argument('--json', action='store_true')
    scan_parser = commands.add_parser('scan', help='Run a network scan and write a report')
    scan_parser.add_argument('--config', default=argparse.SUPPRESS)
    scan_parser.add_argument('--json', action='store_true')
    scan_modes = scan_parser.add_mutually_exclusive_group()
    scan_modes.add_argument('--quick', action='store_true', default=argparse.SUPPRESS)
    scan_modes.add_argument('--deep', action='store_true', default=argparse.SUPPRESS)
    check_link = commands.add_parser('check-link', help='Check a link against the local cache')
    check_link.add_argument('url')
    check_link.add_argument('--config', default=argparse.SUPPRESS)
    check_link.add_argument('--json', action='store_true')
    explain_parser = commands.add_parser('explain', help='Explain one saved finding with the local model')
    approve_parser = commands.add_parser('approve', help='Record a human approval for one finding')
    approve_parser.add_argument('--reason')
    for finding_parser in (explain_parser, approve_parser):
        finding_parser.add_argument('finding_id')
        finding_parser.add_argument('--config', default=argparse.SUPPRESS)
        finding_parser.add_argument('--json', action='store_true')
    feed_commands = commands.add_parser('feeds', help='Manage the local feed cache').add_subparsers(required=True)
    feed_update = feed_commands.add_parser('update', help='Refresh the cache from the configured source')
    feed_update.add_argument('--config', default=argparse.SUPPRESS)
    feed_update.add_argument('--json', action='store_true', help='Print the outcome as JSON')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--approve-baseline', action='store_true')
    modes.add_argument('--test-notification', action='store_true')
    modes.add_argument('--notify-failure', action='store_true')
    modes.add_argument('--quick', action='store_true', help='scan known hosts on baseline ports (default)')
    modes.add_argument('--deep', action='store_true', help='scan the whole scope, all TCP ports, with service names; takes minutes')
    args = parser.parse_args(argv)
    if args.feed_command == 'demo':
        if args.config or args.approve_baseline or args.test_notification or args.notify_failure or args.quick or args.deep:
            parser.error('demo cannot be combined with other modes')
        print('Sample report. Nothing was scanned and no files were written.\n')
        print(report_text(DEMO_FINDINGS, {}, datetime.now(timezone.utc).strftime(ARCHIVE_STAMP)), end='')
        return 0
    if args.feed_command == 'status':
        if args.approve_baseline or args.test_notification or args.notify_failure or args.quick or args.deep:
            parser.error('status cannot be combined with another mode')
        return status_command(args)
    if args.feed_command in ('setup', 'uninstall'):
        if args.config or args.approve_baseline or args.test_notification or args.notify_failure or args.quick or args.deep:
            parser.error('setup and uninstall use the default paths and cannot be combined with other modes')
        return management_command(args)
    if not args.config and wizard.setup_config().is_file():
        args.config = str(wizard.setup_config())
    if args.feed_command in ('explain', 'approve'):
        if args.approve_baseline or args.test_notification or args.notify_failure or args.quick or args.deep:
            parser.error('finding commands cannot be combined with another mode')
        return finding_command(args)
    scan_command = args.feed_command == 'scan'
    json_output = scan_command and args.json
    profile = 'deep' if args.deep else 'quick'
    if scan_command:
        if args.approve_baseline or args.test_notification or args.notify_failure or (args.quick and args.deep):
            parser.error('scan cannot be combined with another mode')
    elif args.feed_command:
        if args.approve_baseline or args.test_notification or args.notify_failure:
            parser.error('feed commands cannot be combined with other modes')
        if not args.config:
            parser.error('--config is required for feed commands')
        if args.feed_command == 'feeds':
            return management_command(args)
        return feeds.run_command(args)
    if args.test_notification or args.notify_failure:
        target = notify.LEGACY_TARGET
        if args.config and (Path(args.config).is_file() or notify.TOPIC_ENV not in os.environ):
            try:
                settings = json.loads(Path(args.config).read_text())
                if 'ntfy' in settings:
                    target = settings['ntfy']
                    if target is not None:
                        target = validate_ntfy(target)
            except (OSError, ValueError, TypeError):
                print('Could not read notification configuration.', file=sys.stderr)
                return 2
        outcome = notify.send(mode='test' if args.test_notification else 'failure', target=target)
        if outcome['status'] == 'accepted':
            print('Notification accepted.' + (' ID: ' + outcome['id'] if 'id' in outcome else ''))
            return 0
        print('Notification disabled.' if outcome['status'] == 'disabled' else 'Notification failed (' + outcome['error_type'] + ').')
        return 0 if outcome['status'] == 'disabled' else 2
    if not args.config and not json_output:
        parser.error('--config is required for normal runs')
    try:
        if not args.config:
            raise ValueError('missing configuration')
        c = config(json.loads(Path(args.config).read_text()))
        if args.deep:
            print('Deep scan started. It can take several minutes.', file=sys.stderr)
        if scan_command:
            return run(c, profile=profile, scan_command=True, json_output=json_output)
        return run(c, args.approve_baseline, profile)
    except Exception as error:
        expected = isinstance(error, (OSError, ValueError, TypeError, KeyError, AttributeError))
        if not json_output and not expected:
            raise
        component = 'configuration_or_io' if expected else 'scan_error'
        failure = finding('coverage', component=component, error_type=type(error).__name__)
        if json_output:
            print(json.dumps(scan_document([failure], profile, c['level'] if 'c' in locals() else None)))
        else:
            print('# Coldguardian\n\n' + json.dumps(failure))
        if isinstance(error, (ScopeError, JournalCorruption)):
            print(error, file=sys.stderr)
        if 'c' in locals() and not json_output and not isinstance(error, JournalCorruption):
            try:
                outdir = Path(c['output_dir'])
                with output_lock(outdir) as locked:
                    if locked:
                        pinned = None
                        with suppress(ValueError, AttributeError):
                            pinned = load_json(outdir / 'state.json', {}).get('report_timestamp')
                        report(outdir, [failure], pinned=pinned, **c['_report_retention'])
            except (OSError, ValueError):
                pass
        return 2


if __name__ == '__main__':
    sys.exit(main())
