import base64
from collections import defaultdict, deque
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import stat
import time
from urllib.parse import urlencode


PAGE_SIZE = 500
PAGE_LIMIT = 32
HISTORY_LIMIT = 32768
WEEK = 7 * 86400


def validate(source, hosts):
    if (not isinstance(source, dict) or not {'provider', 'host'} <= source.keys()
            or source.keys() - {'provider', 'host', 'port', 'credential_file'}
            or source['provider'] not in ('adguard', 'pihole')
            or not isinstance(source['host'], str) or source['host'] not in hosts
            or type(source.get('port', 443)) is not int or not 1 <= source.get('port', 443) <= 65535):
        raise ValueError('dns_api needs a provider, inventory host and valid HTTPS port')
    if 'credential_file' in source:
        path = source['credential_file']
        if not isinstance(path, str) or not Path(path).is_absolute() or '\x00' in path:
            raise ValueError('credential_file must be an absolute path')


def query_page(source, address, params):
    adguard = source['provider'] == 'adguard'
    headers = {}
    if 'credential_file' in source:
        fd = os.open(source['credential_file'], os.O_RDONLY | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError('DNS credential must be a private regular file')
            secret = stream.read(4097).removesuffix(b'\n')
        if not secret or len(secret) > 4095 or not all(32 <= b < 127 for b in secret):
            raise ValueError('invalid DNS credential')
        if adguard:
            headers['Authorization'] = 'Basic ' + base64.b64encode(secret).decode('ascii')
        else:
            headers['X-FTL-SID'] = secret.decode('ascii')
    path = '/control/querylog' if adguard else '/api/queries'
    connection = http.client.HTTPSConnection(address, source.get('port', 443), timeout=5)
    try:
        connection.request('GET', path + '?' + urlencode(params), headers=headers)
        with connection.getresponse() as response:
            if response.status != 200:
                raise ValueError('DNS API request failed')
            data = response.read(2**20 + 1)
            if len(data) > 2**20:
                raise ValueError('DNS API response exceeds limit')
            return json.loads(data)
    finally:
        connection.close()


def api_queries(source, address, previous, now):
    if not isinstance(previous, dict):
        return [], {}, {'log_read'}
    since = previous.get('since', now - 86400)
    until = previous.get('until', now)
    cursor = previous.get('cursor')
    adguard = source['provider'] == 'adguard'
    if (type(since) is not int or type(until) is not int or not 0 <= since <= until <= now
            or cursor is not None and (not isinstance(cursor, str) if adguard else type(cursor) is not int)):
        return [], {}, {'log_read'}
    rows, issues = [], set()
    deadline = time.monotonic() + 20
    try:
        for _ in range(PAGE_LIMIT):
            if time.monotonic() >= deadline:
                break
            if adguard:
                end = cursor or datetime.fromtimestamp(until, timezone.utc).isoformat()
                params = {'limit': PAGE_SIZE, 'older_than': end}
            else:
                params = {'from': since, 'until': until, 'length': PAGE_SIZE, 'start': cursor or 0}
            page = query_page(source, address, params)
            batch = page['data' if adguard else 'queries']
            if not isinstance(batch, list) or len(batch) > PAGE_SIZE:
                raise ValueError('invalid DNS page')
            crossed = False
            for row in batch:
                try:
                    if adguard:
                        stamp = datetime.fromisoformat(row['time'].replace('Z', '+00:00'))
                        if stamp.tzinfo is None:
                            raise ValueError
                        stamp = stamp.timestamp()
                        domain, client = row['question']['name'], row['client']
                    else:
                        stamp, domain, client = row['time'], row['domain'], row['client']['ip']
                    if (type(stamp) not in (float, int) or not math.isfinite(stamp)
                            or not isinstance(domain, str) or not 0 < len(domain) <= 255 or not domain.isascii()
                            or not domain.isprintable()
                            or not isinstance(client, str)):
                        raise ValueError
                    client = str(ipaddress.ip_address(client))
                    if stamp < since:
                        crossed = True
                    elif stamp < until:
                        rows.append((stamp, client, domain))
                except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
                    issues.add('dns_parse')
            if crossed or not batch or (len(batch) < PAGE_SIZE and (not adguard or not page.get('oldest'))):
                return rows, {'since': until}, issues
            if adguard:
                next_cursor = page.get('oldest')
                if not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor:
                    raise ValueError('invalid DNS cursor')
                cursor = next_cursor
            else:
                cursor = (cursor or 0) + len(batch)
        issues.add('log_backlog')
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException, RecursionError, OverflowError):
        issues.add('log_read')
    return rows, {'since': since, 'until': until, 'cursor': cursor}, issues


def first_seen_bursts(rows, history, now):
    cutoff = now - WEEK
    history = history if isinstance(history, dict) else {}
    entries = history.get('seen', {})
    seen = {key: stamp for key, stamp in entries.items()
            if type(stamp) in (float, int) and cutoff <= stamp <= now} if isinstance(entries, dict) else {}
    recent = history.get('recent', {})
    fresh = defaultdict(list)
    for stamp, client, domain in sorted(rows):
        if not cutoff <= stamp <= now or not domain.isascii() or not domain.isprintable():
            continue
        key = hashlib.sha256((client + '\x00' + domain.lower().rstrip('.')).encode()).hexdigest()
        if key not in seen:
            fresh[client].append(stamp)
        seen[key] = max(stamp, seen.get(key, 0))
    counts, tails = {}, {}
    for client in fresh.keys() | (recent.keys() if isinstance(recent, dict) else set()):
        previous = recent.get(client, []) if isinstance(recent, dict) else []
        times = [(t, False) for t in previous if type(t) in (float, int) and cutoff <= t <= now]
        times.extend((t, True) for t in fresh[client])
        window = deque()
        newest_observation = None
        for stamp, is_new in sorted(times):
            while window and window[0] < stamp - 60:
                window.popleft()
            window.append(stamp)
            if is_new:
                newest_observation = stamp
            if newest_observation is not None and newest_observation >= stamp - 60 and len(window) >= 10:
                counts[client] = max(len(window), counts.get(client, 0))
        if window and window[-1] >= now - 60:
            tails[client] = list(window)
    if len(seen) > HISTORY_LIMIT:
        seen = dict(sorted(seen.items(), key=lambda entry: entry[1])[-HISTORY_LIMIT:])
    return counts, {'seen': seen, 'recent': tails}
