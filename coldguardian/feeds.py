import csv
import hashlib
from http.client import HTTPException
import io
import json
import os
from pathlib import Path
import re
import string
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import ProxyHandler, build_opener

from .notify import NoRedirect
from .report import COVERAGE_MESSAGES, atomic_json, load_json
from .scan import finding


MAX_AGE = 48 * 60 * 60
MAX_BYTES = 32 * 1024 * 1024
CACHE_NAME = 'feed-cache.json'
LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?')
ESCAPE = re.compile(r'%([0-9a-fA-F]{2})')
INVALID_ESCAPE = re.compile(r'%(?![0-9a-fA-F]{2})')
UNRESERVED = string.ascii_letters + string.digits + '-._~'


def domain_key(host):
    host = host.lower().removesuffix('.')
    labels = host.split('.')
    if len(host) > 253 or not all(LABEL.fullmatch(label) and not label.startswith('xn--') for label in labels):
        return None
    if re.fullmatch(r'[0-9]+|0x[0-9a-f]*', labels[-1]):
        return None
    return host


def normalize_escape(match):
    char = chr(int(match[1], 16))
    return char if char in UNRESERVED else match[0].upper()


def normalize_path(path):
    segments = []
    for segment in path[1:].split('/'):
        if segment == '..':
            if segments:
                segments.pop()
        elif segment != '.':
            segments.append(segment)
    if path.endswith(('/.', '/..')):
        segments.append('')
    return '/' + '/'.join(segments)


def url_key(url):
    if not isinstance(url, str) or not url or any(c.isspace() or ord(c) < 32 or c in '\\\x7f' for c in url):
        return None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ('http', 'https') or not parts.hostname or '[' in parts.netloc:
        return None
    host = domain_key(ESCAPE.sub(normalize_escape, parts.hostname))
    if host is None or any(INVALID_ESCAPE.search(value) for value in (parts.path, parts.query)):
        return None
    if port is not None and port != (443 if parts.scheme == 'https' else 80):
        host += f':{port}'
    path = normalize_path(ESCAPE.sub(normalize_escape, parts.path or '/'))
    query = ESCAPE.sub(normalize_escape, parts.query)
    return urlunsplit((parts.scheme, host, path, query, ''))


def parse_tweetfeed(data):
    links, domains = set(), set()
    for row in csv.reader(io.StringIO(data), strict=True):
        if not row:
            continue
        if len(row) != 6:
            raise ValueError('invalid TweetFeed row')
        _, _, kind, value, _, _ = row
        if kind == 'url' and (link := url_key(value)):
            links.add(link)
        elif kind == 'domain' and (domain := domain_key(value)):
            domains.add(domain)
    if not links:
        raise ValueError('feed contains no usable links')
    return links, domains


def source_id(feed):
    if not isinstance(feed, dict) or set(feed) not in ({'path'}, {'url'}):
        raise ValueError('use one absolute fixture path or an HTTPS feed URL')
    if 'path' in feed:
        if not isinstance(feed['path'], str) or not Path(feed['path']).is_absolute():
            raise ValueError('use one absolute fixture path or an HTTPS feed URL')
        location = feed['path']
        source_type = 'path'
    else:
        location = feed.get('url')
        normalized = url_key(location)
        if not normalized or not normalized.startswith('https://'):
            raise ValueError('feed URL must use HTTPS')
        parts = urlsplit(location)
        if parts.username is not None or parts.fragment or '{key}' in location:
            raise ValueError('feed URL must be keyless')
        source_type = 'url'
    return hashlib.sha256(json.dumps(['tweetfeed', source_type, location]).encode()).hexdigest()


def update_cache(outdir, feed):
    source = source_id(feed)
    if 'path' in feed:
        response = Path(feed['path']).open('rb')
        expected_length = None
    else:
        opener = build_opener(ProxyHandler({}), NoRedirect())
        opener.addheaders = [('User-Agent', 'Coldguardian')]
        response = opener.open(feed['url'], timeout=30)
        expected_length = response.headers.get('Content-Length')
    with response:
        raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError('feed exceeds size limit')
    if expected_length is not None and len(raw) != int(expected_length):
        raise ValueError('incomplete feed download')
    links, domains = parse_tweetfeed(raw.decode('utf-8-sig'))
    outdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if outdir.is_symlink():
        raise ValueError('output directory cannot be a symlink')
    os.chmod(outdir, 0o700)
    atomic_json(outdir / CACHE_NAME, {
        'source': source, 'updated_at': int(time.time()), 'links': sorted(links), 'domains': sorted(domains),
    })
    return len(links)


def cached_indicators(outdir, feed):
    if feed is None:
        return set(), set(), 'feed_cache_missing', None
    try:
        source = source_id(feed)
        cache = load_json(outdir / CACHE_NAME)
        if cache is None:
            return set(), set(), 'feed_cache_missing', None
        if not isinstance(cache, dict) or cache.get('source') != source:
            raise ValueError('cache does not match the configured feed')
        links, domains, updated_at = cache.get('links'), cache.get('domains'), cache.get('updated_at')
        age = time.time() - updated_at if type(updated_at) is int else -1
        if (age < 0 or not isinstance(links, list) or not links
                or not all(isinstance(link, str) and url_key(link) == link for link in links)
                or not isinstance(domains, list)
                or not all(isinstance(domain, str) and domain_key(domain) == domain for domain in domains)):
            raise ValueError('invalid feed cache')
    except (OSError, ValueError, OverflowError, RecursionError):
        return set(), set(), 'feed_cache_invalid', None
    return set(links), set(domains), 'feed_cache_stale' if age > MAX_AGE else None, updated_at


def read_cache(outdir, feed):
    links, domains, warning, _ = cached_indicators(outdir, feed)
    return links, domains, warning


def run_command(args):
    update = args.feed_command == 'feeds'
    try:
        c = json.loads(Path(args.config).read_text())
        outdir = Path(c.get('output_dir', '/var/lib/coldguardian'))
        if not outdir.is_absolute() or outdir.is_symlink():
            raise ValueError('output directory must be absolute and not a symlink')
        if update:
            count = update_cache(outdir, c.get('feed'))
            print(f'Feed cache updated with {count} links.')
            return 0
        links, domains, warning = read_cache(outdir, c.get('feed'))
    except (OSError, HTTPException, csv.Error, ValueError, TypeError, AttributeError, RecursionError) as error:
        if isinstance(error, HTTPError):
            error.close()
        if update:
            print('Feed update failed. Check the configured source and output directory.')
            return 2
        links, domains, warning = set(), set(), 'feed_cache_invalid'

    link = url_key(args.url)
    host = urlsplit(link).hostname if link is not None else None
    if link in links or host in domains:
        status, code = 'bad', 1
    elif warning or link is None:
        status, code = 'unknown', 2
    else:
        status, code = 'clean', 0
    if args.json:
        coverage = [finding('coverage', component=warning)] if warning else []
        print(json.dumps(dict(status=status, coverage=coverage)))
    else:
        print(status)
        if warning:
            print(COVERAGE_MESSAGES[warning])
    return code
