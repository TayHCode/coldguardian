from collections import deque
import datetime
import json
import os
import re
import resource
import stat
import tempfile

from .scan import AUTH_METHOD, HOST_NAME, PRODUCT, SERVICE, finding, valid_ip
from .rules import RULE_ID


DNS_TELEMETRY = {'dns_long_label', 'dns_entropy'}
REPORT_OBSERVATIONS = {'observed_host', 'scan_summary', 'source_summary', 'service'}
ARCHIVE_STAMP = '%Y%m%dT%H%M%S.%fZ'
DEFAULT_REPORT_COUNT = 50


def evidence_fields(item, index):
    return {
        'check': item.get('rule', item.get('component', item['category'])),
        'evidence_id': f'E{index + 1}',
    }


class JournalCorruption(ValueError):
    pass


class FindingExpired(ValueError):
    pass


def incomplete_record(error):
    doc = error.doc
    if not doc.startswith('{'):
        return False
    tail = doc[error.pos:]
    if error.pos == len(doc) or error.msg.startswith('Unterminated string'):
        return True
    if error.msg == 'Expecting value':
        return tail in ('t', 'tr', 'tru', 'f', 'fa', 'fal', 'fals', 'n', 'nu', 'nul', '-')
    if error.msg.startswith('Invalid \\u'):
        return re.fullmatch(r'u[0-9a-fA-F]{0,4}', tail) is not None
    return (error.msg == "Expecting ',' delimiter" and doc[error.pos - 1].isdigit()
            and re.fullmatch(r'\.|[eE][+-]?', tail) is not None)


def archive_time(stamp):
    if not isinstance(stamp, str) or not re.fullmatch(r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z', stamp):
        raise ValueError('Invalid report timestamp.')
    return datetime.datetime.strptime(stamp, ARCHIVE_STAMP).replace(tzinfo=datetime.timezone.utc)


def journal_rows(outdir):
    try:
        fd = os.open(outdir / 'alerts.jsonl', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    with os.fdopen(fd, 'rb') as log:
        if not stat.S_ISREG(os.fstat(log.fileno()).st_mode):
            raise ValueError('Alert journal must be a regular file.')
        for number, line in enumerate(log, 1):
            try:
                row = json.loads(line.decode('utf-8'))
                created = archive_time(row['timestamp'])
                if 'expired_through' in row:
                    archive_time(row['expired_through'])
                if not isinstance(row['findings'], list) or not all(
                    isinstance(item, dict) and isinstance(item.get('category'), str)
                    for item in row['findings']
                ):
                    raise ValueError('Invalid findings.')
            except (ValueError, KeyError, TypeError) as error:
                if isinstance(error, json.JSONDecodeError) and not line.endswith(b'\n') and incomplete_record(error):
                    return
                raise JournalCorruption(f'Corrupt alert journal at line {number}.') from error
            yield row, created


def saved_finding(outdir, finding_id):
    stamp, separator, key = finding_id.rpartition(':')
    if not re.fullmatch(r'E[1-9][0-9]*', key) or (separator and not stamp):
        raise ValueError('Invalid finding ID.')
    if stamp:
        archive_time(stamp)
    selected = None
    expired = ''
    for row, _ in journal_rows(outdir):
        expired = max(expired, row.get('expired_through', ''))
        if stamp and row['timestamp'] != stamp:
            continue
        if row['findings'] and row['findings'][0]['category'] == 'scan_summary':
            selected = row
    if selected is None and stamp and stamp <= expired:
        raise FindingExpired('Finding ID expired under report retention.')
    if selected is not None:
        for index, item in enumerate(selected['findings'], 1):
            if key == f'E{index}':
                return selected, key, item
    raise ValueError('Finding ID was not found in the saved scan reports.')


def scan_document(findings, profile, level, record=None):
    incomplete = any(
        item['category'] in ('baseline_missing', 'baseline_mismatch') or (
            item['category'] == 'coverage'
            and item.get('component') != 'notification_delivery'
            and not item.get('optional')
        )
        for item in findings
    )
    positive = any(
        item['category'] not in REPORT_OBSERVATIONS | DNS_TELEMETRY
        | {'coverage', 'baseline_missing', 'baseline_mismatch'}
        for item in findings
    )
    exit_code = 1 if positive else 2 if incomplete else 0
    return {
        'schema_version': 1,
        'profile': profile,
        'level': level,
        'status': ('clean', 'bad', 'incomplete')[exit_code],
        'exit_code': exit_code,
        'timestamp': datetime.datetime.strptime(record['timestamp'], ARCHIVE_STAMP)
                     .isoformat(timespec='microseconds') + 'Z' if record else None,
        'scanner_peak_rss_kib': (record['scanner_peak_rss_kib'] if record else
                                 resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
        'findings': [
            dict(item, **evidence_fields(item, i),
                 **({'finding_id': f"{record['timestamp']}:E{i + 1}"} if record else {}))
            for i, item in enumerate(map(safe_finding, findings))
        ],
    }


COVERAGE_MESSAGES = {
    'lan_discovery': 'Local network discovery failed. Next step: check scanner access and retry.',
    'host_discovery': 'Inventory discovery failed. Next step: check network connectivity to the inventory hosts and retry.',
    'host_offline': 'An inventory device did not respond. Next step: check whether it is powered on and connected.',
    'tcp_scan': 'The port scan did not finish. Next step: check scanner access and retry.',
    'tailscale_status': 'The Tailscale peer list could not be read. The previous list was retained.',
    'wireguard_discovery': 'Some approved WireGuard addresses could not be selected. Check local WireGuard interfaces and retry.',
    'log_read': 'A log source could not be read. Next step: check log access and retry; its saved cursor was retained.',
    'log_backlog': 'Some log data remains unread. Next step: let the next run continue; check the source if this persists.',
    'log_rotated': 'A log rotated or was truncated. Next step: review log rotation for a possible coverage gap.',
    'log_history_skipped': 'Only the recent log tail was read. Next step: review older history separately if needed.',
    'dns_parse': 'Some DNS rows could not be parsed. Next step: check the source log format.',
    'feed_cache_missing': 'The local feed cache is missing. Run coldguardian feeds update.',
    'feed_cache_invalid': 'The local feed cache or configuration is invalid. Check the configuration and refresh the feed.',
    'feed_cache_stale': 'The local feed cache is older than 48 hours. Run coldguardian feeds update.',
    'state_read': 'Saved monitoring state could not be read. Next step: check the private state file before retrying.',
    'baseline_read': 'The saved network reference could not be read. Next step: review the reference file.',
    'baseline_approval': 'The network reference could not be approved. Next step: obtain a complete matching scan and review it.',
    'configuration_or_io': 'Configuration or report storage failed. Next step: check configuration and private output storage.',
    'scan_error': 'The scan stopped because of an unexpected error.',
    'overlapping_run': 'Another monitoring run is active. Next step: wait for that run to finish.',
    'notification_delivery': 'Phone notification delivery failed. Next step: check private notification configuration and connectivity; a summary remains pending for retry.',
}


def atomic_text(path, text):
    fd, name = tempfile.mkstemp(prefix='.coldguardian-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            os.fchmod(out.fileno(), 0o600)
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, sort_keys=True) + '\n')


def load_json(path, default=None):
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def private_file(path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'w')


def safe_finding(f):
    categories = {'new_device', 'new_ports', 'observed_host', 'auth_failed', 'dns_suffix', 'dns_long_label', 'dns_entropy', 'coverage', 'baseline_missing', 'baseline_mismatch', 'baseline_scope_review', 'baseline_approved', 'baseline_enrolled', 'scan_summary', 'source_summary',
                  'service', 'dns_feed_match', 'link_feed_hit', 'login_burst', 'risky_service', 'peer_change', 'baseline_drift'}
    category = f.get('category')
    result = {'category': category if isinstance(category, str) and category in categories else 'other'}
    for key in ('ip', 'client_ip'):
        if valid_ip(f.get(key)):
            result[key] = valid_ip(f[key])
    if isinstance(f.get('host'), str) and HOST_NAME.fullmatch(f['host']):
        result['host'] = f['host']
    if f.get('optional') is True:
        result['optional'] = True
    if f.get('kind') in ('dns', 'auth'):
        result['kind'] = f['kind']
    if isinstance(f.get('component'), str) and f['component'] in COVERAGE_MESSAGES:
        result['component'] = f['component']
    for key in ('count', 'host_count', 'log_sources', 'approved_hosts', 'window_seconds'):
        if type(f.get(key)) is int and f[key] >= 0:
            result[key] = f[key]
    if isinstance(f.get('ports'), list):
        result['ports'] = [p for p in f['ports'] if type(p) is int and 1 <= p <= 65535]
    if type(f.get('port')) is int and 1 <= f['port'] <= 65535:
        result['port'] = f['port']
    if category == 'peer_change' and f.get('change') in ('added', 'removed'):
        result['change'] = f['change']
    if category == 'risky_service' and isinstance(f.get('rule'), str) and RULE_ID.fullmatch(f['rule']):
        result['rule'] = f['rule']
    if category == 'source_summary' and f.get('status') in ('ok', 'partial'):
        result['status'] = f['status']
    if category == 'coverage' and isinstance(f.get('error_type'), str) and f['error_type'].isidentifier():
        result['error_type'] = f['error_type']
    for key, pattern in (('service', SERVICE), ('product', PRODUCT)):
        if isinstance(f.get(key), str) and pattern.fullmatch(f[key]):
            result[key] = f[key]
    if isinstance(f.get('auth_methods'), list):
        result['auth_methods'] = [m for m in f['auth_methods'] if isinstance(m, str) and AUTH_METHOD.fullmatch(m)]
    for key in ('network_complete', 'log_coverage_complete'):
        if type(f.get(key)) is bool:
            result[key] = f[key]
    return result


MODEL_OBSERVATION_VALUES = {
    'category': {
        'approved_policy', 'device', 'dns_query', 'exact_feed_lookup', 'feed_record',
        'feed_status', 'http_response', 'inventory', 'link_check', 'maintenance',
        'owner_confirmation', 'port_observation', 'service_observation',
    },
    'authentication': {'none', 'required', 'unknown', 'mutual TLS'},
    'category_in_feed': {'phishing', 'malware'},
    'component': {'feed', 'network'},
    'path': {'/v1/models', '/v1/chat/completions'},
    'source': {'tailscale', 'wireguard'},
    'state': {'open', 'closed', 'filtered'},
    'status': {'clean', 'bad', 'unknown'},
}


def model_observation(finding):
    result = safe_finding(finding)
    result.pop('product', None)
    for field, allowed in MODEL_OBSERVATION_VALUES.items():
        value = finding.get(field)
        if isinstance(value, str) and value in allowed:
            result[field] = value
    for field in ('age_hours', 'cache_age_hours', 'distinct_accounts', 'feed_age_hours', 'last_seen_days'):
        value = finding.get(field)
        if type(value) is int and value >= 0:
            result[field] = value
    for field in ('approved', 'authenticated', 'confirmed', 'exact_match', 'feed_match',
                  'guest_read', 'scheduled', 'telnet_login_prompt'):
        value = finding.get(field)
        if type(value) is bool:
            result[field] = value
    for field, flag in (('owner', 'owner_known'), ('owner_confirmation', 'owner_confirmation_recorded')):
        if field in finding and (finding[field] is None or isinstance(finding[field], str)):
            result[flag] = bool(finding[field] and finding[field].strip())
    if isinstance(finding.get('source_ip'), str) and (source_ip := valid_ip(finding['source_ip'])):
        result['source_ip'] = source_ip
    status = finding.get('status')
    if result['category'] == 'http_response' and type(status) is int and 100 <= status <= 599:
        result['status'] = status
    ports = finding.get('approved_ports')
    if isinstance(ports, list) and all(type(port) is int and 1 <= port <= 65535 for port in ports):
        result['approved_ports'] = ports
    methods = finding.get('ssh_auth_methods')
    if isinstance(methods, list) and all(isinstance(method, str) and AUTH_METHOD.fullmatch(method) for method in methods):
        result['ssh_auth_methods'] = methods
    return result


def literal_markdown(text):
    longest_run = max((len(run) for run in re.findall(r'`+', text)), default=0)
    fence = '`' * (longest_run + 1)
    return f'{fence} {text} {fence}'


def with_explanation(line, key, result):
    if result is None:
        return f'{key}. {line} Local model unavailable.'
    citations = ', '.join(result['evidence_ids'])
    line = f"{key}. {line} Model label: {result['label']} ({citations}). " + literal_markdown(result['reason'])
    if result['missing']:
        line += ' Missing evidence: ' + ', '.join(map(literal_markdown, result['missing']))
    return line


def report_text(findings, explanations, stamp, *, scanner_peak_rss_kib=None):
    safe = [safe_finding(f) for f in findings]
    security, coverage, observations, services = [], [], [], []
    attention = any(f['category'] not in DNS_TELEMETRY | {'scan_summary', 'source_summary', 'baseline_approved', 'baseline_enrolled', 'service'} for f in safe)
    for index, (raw, f) in enumerate(zip(findings, safe)):
        category = f['category']
        section = security
        address = f.get('ip', 'an unlisted address')
        source = ' on ' + f['host'] if 'host' in f else ''
        if 'kind' in f:
            source += ' (' + f['kind'] + ')'
        client = ' from ' + f['client_ip'] if 'client_ip' in f else ''
        count = str(f.get('count', 0))
        if category == 'new_device':
            line = 'New device observed at ' + address + '. Next step: identify it and review inventory before approving it.'
        elif category in ('new_ports', 'observed_host'):
            ports = ', '.join(map(str, f.get('ports', []))) or 'none observed'
            line = ('New open TCP ports at ' if category == 'new_ports' else 'Observed device at ') + address + ': ' + ports + '. Next step: review these ports and the device owner.'
        elif category == 'dns_feed_match':
            line = 'DNS queries matched a host in the local feed' + source + client + ': ' + count + '.'
        elif category == 'login_burst':
            line = f'Failed SSH sign-in burst{source}{client}: {count} failures within {f.get("window_seconds", 0)} seconds.'
        elif category == 'peer_change':
            line = f'Tailscale peer {address} {f.get("change", "changed")}.'
        elif category == 'baseline_drift':
            ports = ', '.join(map(str, f.get('ports', [])))
            line = f'Previously approved TCP ports at {address} were no longer observed open: {ports}.'
        elif category == 'risky_service' and 'rule' in f and 'port' in f and 'title' in raw and 'reason' in raw:
            line = f'{raw["title"]} ({address}:{f["port"]}). {raw["reason"]}'
        elif category in DNS_TELEMETRY | {'dns_suffix', 'auth_failed'}:
            label = {'dns_long_label': 'Long DNS label', 'dns_entropy': 'High-entropy DNS label', 'dns_suffix': 'Configured DNS suffix match', 'auth_failed': 'Failed authentication'}[category]
            line = label + ' events' + source + client + ': ' + count + '. Low-confidence indicator; this count does not confirm an attack.'
            if category in DNS_TELEMETRY:
                section = observations
            else:
                line += ' Next step: ' + ('review expected sign-in failures.' if category == 'auth_failed' else 'review expected device or application activity.')
        elif category == 'coverage':
            section = coverage
            location = ('Source' + source + '. ') if source else (f'Address {address}. ' if 'ip' in f else '')
            line = location + COVERAGE_MESSAGES.get(f.get('component'), 'A monitoring check is incomplete. Next step: review local monitoring configuration.') + ((' Unparsed rows: ' + count + '.') if f.get('component') == 'dns_parse' else '')
        elif category == 'baseline_missing':
            line = 'No approved network reference exists. Next step: review the observed inventory and explicitly approve a reference.'
        elif category in ('baseline_mismatch', 'baseline_scope_review'):
            line = 'The network reference needs scope review. Next step: compare the approved inventory with the current configuration.'
        elif category == 'baseline_approved':
            line = 'Network reference explicitly approved. Future changes remain monitored.'
        elif category == 'baseline_enrolled':
            line = 'Initial network reference saved. Future changes remain monitored.' + ((' Approved hosts: ' + str(f['approved_hosts']) + '.') if 'approved_hosts' in f else '')
        elif category == 'scan_summary':
            section = coverage
            line = 'Scan observed ' + str(f.get('host_count', 0)) + ' hosts. Network scan ' + ('complete' if f.get('network_complete') else 'incomplete') + '; log coverage ' + ('complete' if f.get('log_coverage_complete') else 'incomplete') + ' across ' + str(f.get('log_sources', 0)) + ' sources.'
        elif category == 'service':
            section = services
            line = address + ':' + str(f.get('port', '?')) + ' ' + f.get('service', 'unknown') + ((' (' + f['product'] + ')') if 'product' in f else '') + ((', SSH sign-in methods: ' + ', '.join(f['auth_methods'])) if 'auth_methods' in f else '')
        elif category == 'source_summary':
            continue
        else:
            line = 'An additional finding needs review. Next step: review the local monitoring checks.'
        evidence = evidence_fields(f, index)
        key = evidence['evidence_id']
        if key in explanations:
            line = with_explanation(line, key, explanations[key])
        section.append(f'{line} [{evidence["check"]}, {key}]')
    text = '# ' + ('Attention needed' if attention else 'No new security findings') + '\n\nColdguardian ' + stamp + '\n\n'
    if scanner_peak_rss_kib is not None:
        text += f'Scanner peak RSS: {scanner_peak_rss_kib} KiB\n\n'
    text += '\n'.join('- ' + line for line in security) if security else 'No new security findings were observed in the completed checks.'
    text += '\n\n## Coverage\n\n' + ('\n'.join('- ' + line for line in coverage) if coverage else 'No coverage issues were reported.')
    if services:
        text += '\n\n## Services seen\n\n' + '\n'.join('- ' + line for line in services)
    if observations:
        text += '\n\n## Informational DNS patterns\n\n' + '\n'.join('- ' + line for line in observations)
    text += '\n\nProposed actions require human review. No actions executed.\n'
    return text


def prune_reports(outdir, stamp, now, pinned, *, max_age_days, max_count):
    archives = []
    for path in outdir.glob('????????T??????.??????Z.md'):
        if path.stem == stamp:
            continue
        try:
            created = datetime.datetime.strptime(path.stem, ARCHIVE_STAMP).replace(tzinfo=now.tzinfo)
        except ValueError:
            continue
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid() or metadata.st_nlink != 1):
            continue
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as archive:
            if (archive.readline(64) not in (b'# Attention needed\n', b'# No new security findings\n')
                    or archive.readline(2) != b'\n'
                    or archive.readline(64) != f'Coldguardian {path.stem}\n'.encode('ascii')):
                continue
        archives.append((created, path))
    for position, (created, path) in enumerate(sorted(archives, reverse=True), start=1):
        if path.stem != pinned and (position >= max_count
                or (max_age_days is not None and (now - created).total_seconds() >= max_age_days * 86400)):
            path.unlink()


def retained_history(outdir, now, pinned, max_age_days, max_count):
    recent = deque()
    extra = None
    expired = ''
    for row, created in journal_rows(outdir):
        expired = max(expired, row.pop('expired_through', ''))
        recent.append((row, created))
        if len(recent) >= max_count:
            removed, _ = recent.popleft()
            if removed['timestamp'] == pinned:
                extra = removed
            else:
                expired = max(expired, removed['timestamp'])
    kept = []
    for row, created in recent:
        if max_age_days is None or (now - created).days < max_age_days:
            kept.append(row)
        elif row['timestamp'] == pinned:
            extra = row
        else:
            expired = max(expired, row['timestamp'])
    return kept, extra, expired


def save_history(outdir, rows, extra, record, expired):
    if expired:
        record['expired_through'] = expired
    path = outdir / 'alerts.jsonl'
    if not path.exists():
        with private_file(path) as log:
            log.write(json.dumps(record, sort_keys=True) + '\n')
            log.flush()
            os.fsync(log.fileno())
        return
    history = ([extra] if extra else []) + rows + [record]
    atomic_text(path, ''.join(json.dumps(row, sort_keys=True) + '\n' for row in history))


def report(outdir, findings, explanations=None, notify=None, *, emit=True, max_age_days=None,
           max_count=DEFAULT_REPORT_COUNT, pinned=None, save_scan=None):
    explanations = explanations or {}
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp = now.strftime(ARCHIVE_STAMP)
    rows, extra, expired = retained_history(outdir, now, pinned, max_age_days, max_count)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    text = report_text(findings, explanations, stamp, scanner_peak_rss_kib=peak)
    with private_file(outdir / (stamp + '.md')) as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    outcome = None
    if notify is not None:
        directory = os.open(outdir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        outcome = notify()
        if outcome['status'] == 'failed':
            findings.append(finding('coverage', component='notification_delivery'))
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        text = report_text(findings, explanations, stamp, scanner_peak_rss_kib=peak)
        messages = {'accepted': 'Phone notification accepted.', 'failed': COVERAGE_MESSAGES['notification_delivery'],
                    'disabled': 'Phone notifications are disabled.', 'unchanged': 'Phone notification suppressed for an unchanged active incident.',
                    'quiet': 'No phone notification was needed.'}
        text += '\n' + messages[outcome['status']] + '\n'
        atomic_text(outdir / (stamp + '.md'), text)
    record = {'timestamp': stamp, 'scanner_peak_rss_kib': peak,
              'findings': findings, 'model_explanations': explanations}
    record['evidence'] = [evidence_fields(f, i) for i, f in enumerate(findings)]
    if outcome is not None:
        record['notification'] = outcome
    save_history(outdir, rows, extra, record, expired)
    atomic_text(outdir / 'latest.md', text)
    if save_scan is not None:
        save_scan(stamp)
        pinned = stamp
        if extra:
            save_history(outdir, rows, None, record, max(expired, extra['timestamp']))
    prune_reports(outdir, stamp, now, pinned, max_age_days=max_age_days, max_count=max_count)
    if emit:
        print(text)
    return record
