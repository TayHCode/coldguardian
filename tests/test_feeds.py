from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError

from coldguardian import cli, feeds, notify
from test_scan_report import SCHEMA, matches_contract


FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'feeds'
BAD_LINK = 'https://bad.example/sign-in?account=1'
CLEAN_LINK = 'https://bad.example/sign-in?account=2'
LINK_SCHEMA = json.loads(SCHEMA.with_name('check-link.schema.json').read_text())
OUTCOME_SCHEMA = json.loads(SCHEMA.with_name('command-outcome.schema.json').read_text())


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.config_path = self.root / 'config.json'
        self.outdir = self.root / 'state'
        self.config = {'output_dir': str(self.outdir)}
        self.configure_feed(path=str(FIXTURES / 'tweetfeed.csv'))

    def configure_feed(self, **feed):
        self.config['feed'] = feed
        self.config_path.write_text(json.dumps(self.config))

    def command(self, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = cli.main([*args, '--config', str(self.config_path)])
        return code, output.getvalue()

    def check_link(self, url, code, status, component=None):
        actual, output = self.command('check-link', url, '--json')
        self.assertEqual(actual, code)
        coverage = [{'category': 'coverage', 'component': component}] if component else []
        self.assertEqual(json.loads(output), {'status': status, 'coverage': coverage})
        self.assertTrue(matches_contract(json.loads(output), LINK_SCHEMA))

    def test_fixture_link_checks_work_with_sockets_blocked(self):
        with (patch('socket.socket', side_effect=AssertionError('socket opened')),
              patch('socket.getaddrinfo', side_effect=AssertionError('DNS lookup'))):
            self.assertEqual(self.command('feeds', 'update')[0], 0)
            for url in (
                'https://BAD.example.:443/sign-in?account=1#fragment',
                'https://bad.example/steps/../%73ign-in?%61ccount=%31',
                'https://bad.example/steps/%2E%2e/sign-in?account=1',
                'https://reader@bad.example/sign-in?account=1',
                'https://%62ad.example/sign-in?account=1',
                'https://userinfo.example/login',
                'https://github.com/example/one-listed-url',
                'https://bad-dns.example/anything',
            ):
                with self.subTest(url=url):
                    self.check_link(url, 1, 'bad')
            for url in (CLEAN_LINK, 'https://github.com/other', 'http://bad.example/sign-in?account=1',
                        'https://bad.example/steps%2F../sign-in?account=1',
                        'https://bad.example//sign-in?account=1', 'https://metadata.example/'):
                self.check_link(url, 0, 'clean')
            for url in ('http://192.0.2.1/payload', 'http://[2001:db8::1]/', 'http://0xc0000201/',
                        'https://xn--bcher-kva.example/sign-in', 'https://bad.example:bad/',
                        'https://bad.example\ntab/', 'https://bad.example/%g1'):
                self.check_link(url, 2, 'unknown')
            cache = self.outdir / feeds.CACHE_NAME
            self.assertEqual(cache.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('fixture-user', cache.read_text())

    def test_missing_stale_and_invalid_cache_coverage(self):
        self.check_link(CLEAN_LINK, 2, 'unknown', 'feed_cache_missing')
        self.assertEqual(self.command('feeds', 'update')[0], 0)
        path = self.outdir / feeds.CACHE_NAME
        cache = json.loads(path.read_text())
        cache['updated_at'] = int(time.time()) - feeds.MAX_AGE - 1
        path.write_text(json.dumps(cache))
        self.check_link(BAD_LINK, 1, 'bad', 'feed_cache_stale')
        self.check_link('https://bad-dns.example/anything', 1, 'bad', 'feed_cache_stale')
        self.check_link(CLEAN_LINK, 2, 'unknown', 'feed_cache_stale')
        cache['links'].append(None)
        path.write_text(json.dumps(cache))
        self.check_link(BAD_LINK, 2, 'unknown', 'feed_cache_invalid')

    def test_failed_refresh_preserves_cache_and_source_changes_invalidate_it(self):
        fixture = self.root / 'feed.csv'
        fixture.write_bytes((FIXTURES / 'tweetfeed.csv').read_bytes())
        self.configure_feed(path=str(fixture))
        self.assertEqual(self.command('feeds', 'update')[0], 0)
        fixture.write_text(f'{fixture.read_text()}invalid,row\n')
        self.assertEqual(self.command('feeds', 'update')[0], 2)
        fixture.unlink()
        self.check_link(BAD_LINK, 1, 'bad')
        self.configure_feed(path=str(FIXTURES / 'tweetfeed.csv'))
        self.check_link(BAD_LINK, 2, 'unknown', 'feed_cache_invalid')

    def test_feed_update_json_reports_outcome_without_diagnostics(self):
        with redirect_stderr(io.StringIO()) as diagnostics:
            code, output = self.command('feeds', 'update', '--json')
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output), {
                'command': 'feeds update', 'status': 'ok', 'exit_code': 0,
            })
            self.assertTrue(matches_contract(json.loads(output), OUTCOME_SCHEMA))
            self.configure_feed(path=str(self.root / 'missing.csv'))
            code, output = self.command('feeds', 'update', '--json')
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output), {
                'command': 'feeds update', 'status': 'failed', 'exit_code': 2,
            })
            self.assertTrue(matches_contract(json.loads(output), OUTCOME_SCHEMA))
        self.assertIn('Feed update failed.', diagnostics.getvalue())

    def test_link_schema_rejects_responses_outside_the_contract(self):
        warning = {'category': 'coverage', 'component': 'feed_cache_stale'}
        for response in ({'status': 'clean'}, {'status': 'safe', 'coverage': []},
                         {'status': 'bad', 'coverage': [warning, warning]},
                         {'status': 'bad', 'coverage': [dict(warning, component='other')]},
                         {'status': 'bad', 'coverage': [], 'url': BAD_LINK}):
            with self.subTest(response=response):
                self.assertFalse(matches_contract(response, LINK_SCHEMA))

    def test_feed_update_default_output_is_not_json(self):
        code, output = self.command('feeds', 'update')
        self.assertEqual(code, 0)
        self.assertRegex(output, r'^Feed cache updated with \d+ links\.\n$')

    def test_https_update_is_keyless_and_sanitizes_download_failure(self):
        url = 'https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv'
        self.configure_feed(url=url)
        with patch.object(feeds, 'build_opener') as build_opener:
            fetch = build_opener.return_value.open
            data = (FIXTURES / 'tweetfeed.csv').read_bytes()
            response = io.BytesIO(data)
            response.headers = {'Content-Length': str(len(data))}
            fetch.return_value = response
            self.assertEqual(self.command('feeds', 'update')[0], 0)
            fetch.assert_called_once_with(url, timeout=30)
            truncated = io.BytesIO(data[:60])
            truncated.headers = {'Content-Length': str(len(data))}
            fetch.return_value = truncated
            self.assertEqual(self.command('feeds', 'update')[0], 2)
            fetch.side_effect = URLError('fixture-download-detail')
            code, output = self.command('feeds', 'update')
            self.assertEqual(code, 2)
            self.assertNotIn('fixture-download-detail', output)
        self.assertNotIn('fixture-download-detail', (self.outdir / feeds.CACHE_NAME).read_text())
        self.check_link(BAD_LINK, 1, 'bad')

    def test_scan_reports_one_dns_match_per_fixture_and_warns_on_old_cache(self):
        self.assertEqual(self.command('feeds', 'update')[0], 0)
        for file in ('adguard.jsonl', 'pihole.log'):
            with self.subTest(file=file):
                c = cli.config({
                    **self.config, 'lan_cidr': '10.20.30.0/24', 'hosts': {'scanner': '10.20.30.2'},
                    'local_host': 'scanner', 'auth_paths': [],
                    'dns_paths': [str(FIXTURES / file)],
                })
                if file == 'pihole.log':
                    path = self.outdir / feeds.CACHE_NAME
                    cache = json.loads(path.read_text())
                    cache['updated_at'] -= feeds.MAX_AGE + 1
                    path.write_text(json.dumps(cache))
                with (patch.object(cli, 'scan', return_value=({}, [])),
                      patch.dict(os.environ), redirect_stdout(io.StringIO())):
                    os.environ.pop(notify.TOPIC_ENV, None)
                    cli.run(c)
                record = json.loads((self.outdir / 'alerts.jsonl').read_text().splitlines()[-1])
                self.assertEqual([f for f in record['findings'] if f['category'] == 'dns_feed_match'], [{
                    'category': 'dns_feed_match', 'client_ip': '192.0.2.10', 'count': 1,
                    'host': 'scanner', 'kind': 'dns',
                }])
                latest = (self.outdir / 'latest.md').read_text()
                self.assertIn('DNS queries matched a host in the local feed', latest)
                self.assertEqual('older than 48 hours' in latest, file == 'pihole.log')
                self.assertNotIn('bad-dns.example', latest)
                self.assertNotIn('github.com', latest)
