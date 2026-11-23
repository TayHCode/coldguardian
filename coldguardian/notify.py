"""Bounded ntfy messages sent to the configured server without redirects."""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request

from . import exposure, hostwatch
from .levels import DEFAULT_LEVEL, LEVELS
from .endpoints import valid_topic
from .report import qualified_finding_id, safe_finding


TOPIC_ENV = 'COLDGUARDIAN_NTFY_TOPIC_FILE'
LEGACY_TARGET = object()
MAX_LINES = 8
MAX_LINE = 200


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def send(lines=(), *, mode='alert', delayed=False, target=LEGACY_TARGET, finding_id=None):
    if target is None or (target is LEGACY_TARGET and TOPIC_ENV not in os.environ):
        return {'status': 'disabled'}
    if target is LEGACY_TARGET:
        server = 'https://ntfy.sh'
        try:
            with open(os.environ[TOPIC_ENV], 'rb') as source:
                raw = source.read(66)
            topic = raw.decode('ascii').removesuffix('\n')
            if not valid_topic(topic):
                raise ValueError()
        except (OSError, ValueError):
            return {'status': 'failed', 'error_type': 'TopicFileError'}
    else:
        server, topic = target['server'], target['topic']
    if mode not in ('test', 'failure', 'alert', 'digest', 'heartbeat'):
        return {'status': 'failed', 'error_type': 'NotificationModeError'}
    blank = isinstance(target, dict) and target.get('detail') == 'blank'
    if blank:
        title, body = 'Coldguardian', 'Coldguardian has a new alert.'
    elif mode == 'heartbeat':
        title, body = 'Coldguardian weekly heartbeat', '\n'.join(lines)
    elif mode == 'test':
        title, body = 'Coldguardian test', 'Coldguardian test notification. Alert-only monitoring.'
    elif mode == 'failure':
        title, body = 'Coldguardian monitoring incomplete', 'Coldguardian scanner failed to complete; monitoring incomplete. Review the local scanner.'
    else:
        lines = [str(line)[:MAX_LINE] for line in lines]
        shown = lines[:MAX_LINES]
        if len(lines) > MAX_LINES:
            shown.append('+' + str(len(lines) - MAX_LINES) + ' more in the local report.')
        if mode == 'alert':
            title = 'Coldguardian: new on your network'
            if delayed:
                shown.insert(0, 'Delayed from an earlier delivery failure.')
            if finding_id:
                shown.insert(0, 'Saved finding: ' + finding_id)
            shown.append('Alert only; nothing was changed.')
        else:
            title = 'Coldguardian morning digest'
            shown = shown or ['Nothing new since the last digest.']
        body = '\n'.join(shown)
    priority = '3' if not blank and mode in ('test', 'digest', 'heartbeat') else '4'
    request = urllib.request.Request(server + '/' + topic, data=body.encode('ascii', 'replace'),
                                     headers={'Title': title, 'Priority': priority,
                                              'Content-Type': 'text/plain; charset=utf-8'}, method='POST')
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=8) as response:
            if not 200 <= response.status < 300:
                return {'status': 'failed', 'error_type': 'HTTPError'}
            raw = response.read(8193)
        result = {'status': 'accepted'}
        if len(raw) <= 8192:
            try:
                message_id = json.loads(raw).get('id')
                if isinstance(message_id, str) and re.fullmatch(r'[A-Za-z0-9]{12}', message_id) and topic not in message_id and message_id not in topic:
                    result['id'] = message_id
            except (ValueError, AttributeError):
                pass
        return result
    except urllib.error.HTTPError as error:
        try:
            error.close()
        except Exception:
            pass
        return {'status': 'failed', 'error_type': 'HTTPError'}
    except Exception:
        return {'status': 'failed', 'error_type': 'TransportError'}


PAGE_NOTES = {
    'baseline_missing': 'No approved network reference exists. Review the report, then approve one.',
    'baseline_mismatch': 'The network reference no longer matches the configuration. Review the report.',
    'baseline_scope_review': 'The network reference needs scope review. Review the report.',
}
FINDING_LABELS = {
    'auth_failed': 'Failed sign-ins',
    'dns_suffix': 'Configured DNS suffix matches',
    'dns_long_label': 'Long DNS labels',
    'dns_first_seen_burst': 'Burst of first-seen DNS names',
    'dns_entropy': 'High-entropy DNS labels',
    'dns_feed_match': 'DNS queries matched the local feed',
    'link_feed_hit': 'Known-bad link match',
    'login_burst': 'Failed sign-in burst',
    'peer_change': 'Peer change',
    'baseline_drift': 'Baseline drift',
}
ROUTINE_CATEGORIES = {'baseline_approved', 'baseline_enrolled', 'host_listener', 'observed_host', 'scan_summary', 'source_summary'}
COVERAGE_EVENTS = {
    *exposure.STATUS, *hostwatch.GAPS,
    'lan_discovery', 'host_discovery', 'host_offline', 'tcp_scan', 'tailscale_status', 'wireguard_discovery',
    'log_read', 'log_backlog', 'dns_parse', 'state_read',
    'baseline_read', 'baseline_approval', 'configuration_or_io', 'overlapping_run',
    'feed_cache_missing', 'feed_cache_invalid', 'feed_cache_stale',
}
PAGED_TTL = 14 * 24 * 60 * 60
MAX_SAVED = 200
DIGEST_HOUR = 8


def notification_items(findings, approvals=(), *, stamp=None, group_by_origin=False):
    safe = [(safe_finding(f), f.get('model_label') == 'needs_human') for f in findings]
    risky_hosts = {item['ip'] for item, _ in safe if item['category'] == 'risky_service' and 'ip' in item}
    items = {}
    for index, (item, needs_human) in enumerate(safe):
        category = item['category']
        if category in ROUTINE_CATEGORIES:
            continue
        route = findings[index].get('delivery_class')
        if item in approvals and route != 'hard_page' and not (category == 'new_device' and item.get('ip') in risky_hosts):
            continue
        ip, host, client = item.get('ip', 'an unlisted address'), item.get('host', ''), item.get('client_ip', '')
        where = (' on ' + host if host else '') + (' from ' + client if client else '')
        count = 1
        event = category
        if category == 'new_device':
            key, text = 'new_device:' + ip, 'New device at ' + ip
            if ip in risky_hosts:
                event = 'risky_new_device'
                text += ' has a risky service open'
            elif route == 'hard_page' and item.get('ports'):
                event = 'risky_new_device'
                text += ' exposes risky TCP ports ' + ', '.join(map(str, item['ports']))
        elif category == 'new_ports':
            ports = ', '.join(map(str, item.get('ports', [])))
            key, text = 'new_ports:' + ip + ':' + ports, 'New open ports on ' + ip + ': ' + ports
        elif category == 'risky_service':
            endpoint = ip + (':' + str(item['port']) if 'port' in item else '')
            rule = item.get('rule', '')
            key = 'risky_service:' + endpoint + (':' + rule if rule else '')
            text = 'Risky service on ' + endpoint + (' (' + rule + ')' if rule else '')
        elif category == 'peer_change' and 'change' in item:
            key = 'peer_change:' + item['change'] + ':' + ip
            text = 'Tailscale peer ' + ip + ' ' + item['change']
        elif category == 'baseline_drift' and 'ports' in item:
            ports = ', '.join(map(str, item.get('ports', [])))
            key = 'baseline_drift:' + ip + ':' + hashlib.sha256(ports.encode()).hexdigest()
            text = 'Previously approved ports no longer observed open on ' + ip + ': ' + ports
        elif category == 'persistence_drift':
            identity = json.dumps([ip, item.get('path'), item.get('sha256')])
            key = category + ':' + hashlib.sha256(identity.encode()).hexdigest()
            text = 'Persistence file ' + item.get('change', 'changed') + where + '. Review the local report.'
            event = 'baseline_drift'
        elif category in ('upnp_mapping', 'tailscale_funnel'):
            text = exposure.description(item)
            key = category + ':' + hashlib.sha256(text.encode()).hexdigest()
        elif category in PAGE_NOTES:
            key, text = category, PAGE_NOTES[category]
        elif category in FINDING_LABELS:
            key, text, count = category + where, FINDING_LABELS[category] + where, item.get('count', 1)
        elif category == 'coverage':
            component = item.get('component')
            if component not in COVERAGE_EVENTS or (component == 'host_offline' and item.get('optional')):
                continue
            key, text = 'coverage_' + component + where, 'Monitoring gap: ' + component.replace('_', ' ') + where
        elif needs_human:
            key, text = 'needs_human' + where, 'Finding needs your review' + where
        else:
            continue
        if route == 'hard_page':
            key = 'hard:' + key
        slot = items.setdefault(key, {'text': text, 'count': 0, 'page_events': set()})
        if group_by_origin and (origin := item.get('client_ip') or item.get('ip') or item.get('host')):
            slot['origin'] = origin
        if stamp is not None:
            slot.setdefault('finding_id', qualified_finding_id(stamp, index))
        slot['count'] += count
        if route == 'hard_page':
            slot['page_events'].update(('hard_page', category))
        if route == 'digest':
            continue
        if event in LEVELS['high'].page_events:
            slot['page_events'].add(event)
        if needs_human:
            slot['page_events'].add('needs_human')
    return items


def saved_map(value, valid):
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in list(value.items())[-MAX_SAVED:] if isinstance(k, str) and len(k) <= 300 and valid(v)}


def is_text(value):
    return isinstance(value, str) and len(value) <= MAX_LINE


def is_slot(value):
    return isinstance(value, dict) and is_text(value.get('text')) and type(value.get('count')) is int and value['count'] > 0


def deliver_notification(state, findings, save_pending, now=None, *, level=DEFAULT_LEVEL,
                         target=LEGACY_TARGET, approvals=(), stamp=None, heartbeat=None):
    if target is None or (target is LEGACY_TARGET and TOPIC_ENV not in os.environ):
        return {'status': 'disabled'}
    destination = {} if target is LEGACY_TARGET else {'target': target}
    now = int(time.time()) if now is None else now
    saved = state.get('notification')
    saved = saved if isinstance(saved, dict) else {}
    paged = saved_map(saved.get('paged'), lambda t: type(t) is int and 0 <= now - t < PAGED_TTL)
    allowed = LEVELS[level].page_events | {'hard_page'}
    items = notification_items(findings, approvals, stamp=stamp, group_by_origin=heartbeat is not None)
    for summary in findings:
        if summary['category'] == 'source_summary' and summary.get('exposure_status') in ('clear', 'exposed'):
            category = {'upnp': 'upnp_mapping', 'tailscale_funnel': 'tailscale_funnel'}[summary['component']]
        elif (summary['category'] == 'source_summary' and summary.get('scope') == hostwatch.SCOPE
              and not any(f.get('component') in ('host_persistence', 'host_baseline') for f in findings)):
            category = 'persistence_drift'
        else:
            continue
        prefix = f'hard:{category}:'
        paged = {key: sent_at for key, sent_at in paged.items() if not key.startswith(prefix) or key in items}
    exact_approvals = [item for item in approvals if 'count' not in item]
    muted_keys = notification_items(exact_approvals).keys() - items.keys()
    pending = {}
    for key, value in saved_map(saved.get('pending'), lambda v: is_text(v) or isinstance(v, dict)).items():
        if key in muted_keys:
            continue
        if is_text(value):
            value = {'text': value, 'page_events': [key.partition(':')[0]]}
        events = value.get('page_events')
        if is_text(value.get('text')) and isinstance(events, list) and all(isinstance(e, str) for e in events) and allowed.intersection(events):
            pending[key] = value
    digest = {key: value for key, value in saved_map(saved.get('digest'), is_slot).items()
              if key not in muted_keys}
    for key, item in items.items():
        slot = digest.setdefault(key, {'text': item['text'], 'count': 0})
        slot['count'] += item['count']
    delayed = bool(pending)
    pages = {key: item for key, item in items.items() if item['page_events'] & allowed}
    for key, item in pages.items():
        if key not in paged:
            previous = pending.get(key, {})
            events = item['page_events'] | set(previous.get('page_events', []))
            pending[key] = {'text': item['text'][:MAX_LINE], 'page_events': sorted(events)}
            if heartbeat is not None and item.get('origin'):
                pending[key]['origin'] = item['origin']
            finding_id = previous.get('finding_id') or item.get('finding_id')
            if finding_id:
                pending[key]['finding_id'] = finding_id
    local, day = time.localtime(now), time.strftime('%Y-%m-%d', time.localtime(now))
    digest_day = saved.get('digest_day')
    digest_due = local.tm_hour >= DIGEST_HOUR and digest_day != day
    state['notification'] = {'paged': paged, 'pending': pending, 'digest': digest, 'digest_day': digest_day}
    outcomes = []
    last_heartbeat = saved.get('heartbeat_at')
    heartbeat_due = heartbeat is not None and (type(last_heartbeat) is not int or now - last_heartbeat >= 7 * 86400)
    if type(last_heartbeat) is int:
        state['notification']['heartbeat_at'] = last_heartbeat
    if pending or digest_due or heartbeat_due:
        save_pending()
    if pending:
        ordered = sorted(pending.values(), key=lambda item: item['text'])
        finding_id = next((item['finding_id'] for item in ordered
                           if isinstance(item.get('finding_id'), str)
                           and re.fullmatch(r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z:E[1-9][0-9]*',
                                            item['finding_id'])), None)
        lines = [item['text'] for item in ordered]
        if heartbeat is not None:
            lines = [line for brief in incident_briefs(ordered) for line in brief]
        outcome = send(lines, delayed=delayed,
                       **({'finding_id': finding_id} if finding_id else {}), **destination)
        outcomes.append(outcome)
        if outcome['status'] == 'accepted':
            paged.update({key: now for key in pending})
            pending.clear()
    if digest_due:
        lines = [slot['text'] + (' (x' + str(slot['count']) + ')' if slot['count'] > 1 else '') for _, slot in sorted(digest.items())]
        outcome = send(lines, mode='digest', **destination)
        outcomes.append(outcome)
        if outcome['status'] == 'accepted':
            digest.clear()
            state['notification']['digest_day'] = day
    if heartbeat_due:
        result = send([heartbeat], mode='heartbeat', **destination)
        outcomes.append(result)
        if result['status'] == 'accepted':
            state['notification']['heartbeat_at'] = now
    outcome = (next((o for o in outcomes if o['status'] == 'failed'), None) or next((o for o in outcomes if o['status'] == 'accepted'), None)
               or {'status': 'unchanged' if pages else 'quiet'})
    state['notification']['delivery'] = outcome
    return outcome


def incident_briefs(items):
    grouped = {}
    for item in items:
        grouped.setdefault(item.get('origin', 'monitor'), []).append(item)
    for origin, group in grouped.items():
        details = '; '.join(item['text'] for item in group)
        events = {event for item in group for event in item['page_events']}
        if events & {'dns_feed_match', 'dns_suffix', 'link_feed_hit'}:
            reason = 'The observed destination matches a threat indicator.'
        elif 'login_burst' in events:
            reason = 'Repeated sign-in failures can indicate an attempt to gain access.'
        elif events & {'new_ports', 'baseline_drift', 'risky_service', 'risky_new_device'}:
            reason = 'The services exposed on this device warrant review against its approved baseline.'
        else:
            reason = 'This activity meets your configured notification policy.'
        evidence = next((item['finding_id'] for item in group
                         if isinstance(item.get('finding_id'), str) and re.fullmatch(
                             r'[0-9]{8}T[0-9]{6}\.[0-9]{6}Z:E[1-9][0-9]*', item['finding_id'])), None)
        command = 'coldguardian explain ' + evidence if evidence else 'coldguardian status --json'
        yield (f'{origin}: {details}', reason, command)
