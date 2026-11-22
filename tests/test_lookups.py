import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from coldguardian import feeds, lookups, scan


HOST = '10.20.30.4'
FINAL = {'role': 'assistant', 'content': '{"label":"risk"}'}


def call(name, arguments, call_id='call_1'):
    return {'id': call_id, 'type': 'function',
            'function': {'name': name, 'arguments': json.dumps(arguments)}}


def request(*calls):
    return {'role': 'assistant', 'tool_calls': list(calls)}, 'tool_calls'


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.config = scan.config({
            'lan_cidr': '10.20.30.0/24',
            'hosts': {'fixture-host': HOST},
            'tailscale_peers': ['100.64.0.4'],
            'wireguard_subnets': ['10.20.31.0/24', 'fd00:1::/64'],
        })
        self.payload = {'messages': [{'role': 'user', 'content': 'Explain finding F1'}]}
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fixture = Path(__file__).parent / 'fixtures' / 'feeds' / 'tweetfeed.csv'
        feed = {'path': str(fixture.resolve())}
        feeds.update_cache(directory, feed)
        _, domains, warning = feeds.read_cache(directory, feed)
        self.context = lookups.LookupContext(
            self.config, {HOST: [22]}, {HOST: [22, 443]}, {HOST: [22, 443]},
            [{'category': 'service', 'ip': HOST, 'port': 443, 'service': 'https'}],
            domains, warning,
        )

    def test_stub_receives_all_three_results_offline(self):
        send = Mock(side_effect=[
            request(call('baseline_history', {'host': 'fixture-host'})),
            request(call('port_detail', {'host': HOST, 'port': 443}, 'call_2'),
                    call('feed_lookup', {'domain': 'BAD-DNS.EXAMPLE.'}, 'call_3')),
            (FINAL, 'stop'),
        ])
        with (patch('socket.socket', side_effect=AssertionError('socket opened')),
              patch('socket.getaddrinfo', side_effect=AssertionError('DNS lookup')),
              patch('subprocess.run', side_effect=AssertionError('process started'))):
            self.assertEqual(self.context.complete(send, self.payload), FINAL)
        self.assertEqual(send.call_count, 3)
        final_payload = send.call_args.args[0]
        results = {message['tool_call_id']: json.loads(message['content'])
                   for message in final_payload['messages'] if message['role'] == 'tool'}
        self.assertEqual(results, {
            'call_1': {'host': HOST, 'approved_ports': [22], 'previous_ports': [22, 443]},
            'call_2': {'host': HOST, 'port': 443, 'observed_open': True, 'service': 'https'},
            'call_3': {'domain': 'bad-dns.example', 'status': 'bad', 'coverage': None},
        })

    def assert_refused(self, calls, reason):
        send = Mock(side_effect=calls)
        with (self.assertLogs('coldguardian.lookups', level='WARNING') as logs,
              self.assertRaises(lookups.LookupRefused)):
            self.context.complete(send, self.payload)
        self.assertEqual(logs.output, [f'WARNING:coldguardian.lookups:Model lookup refused: {reason}'])
        self.assertEqual(send.call_count, len(calls))

    def test_stub_cannot_use_unknown_tools_or_an_out_of_scope_host(self):
        self.assert_refused([request(call('model-controlled\ntext', {}))], 'unknown tool')
        for host in ('10.99.99.9', '100.64.0.5', '198.51.100.8', '10.20.30.255'):
            with self.subTest(host=host):
                self.assert_refused([request(call('baseline_history', {'host': host}))], 'host outside scope')

    def test_stub_cannot_use_a_fourth_call_across_rounds(self):
        calls = [call('baseline_history', {'host': HOST}, f'call_{i}') for i in range(4)]
        self.assert_refused([request(*calls[:2]), request(calls[2]), request(calls[3])],
                            'call limit exceeded')
        self.assert_refused([request(*calls)], 'call limit exceeded')

    def test_malformed_arguments_are_refused(self):
        for port in (True, 0, -1, 65536, '443', 443.0):
            with self.subTest(port=port):
                self.assert_refused([request(call('port_detail', {'host': HOST, 'port': port}))],
                                    'invalid port')
        for domain in ('https://bad-dns.example', '10.20.30.4', 'bad..example', 'xn--example.test', 'K.example', None):
            with self.subTest(domain=domain):
                self.assert_refused([request(call('feed_lookup', {'domain': domain}))], 'invalid domain')
        duplicate = call('baseline_history', {'host': HOST})
        duplicate['function']['arguments'] = '{"host":"10.99.99.9","host":"10.20.30.4"}'
        self.assert_refused([request(duplicate)], 'invalid arguments')
        self.assert_refused([request(call('baseline_history', {'host': HOST, 'path': '/etc/passwd'}))],
                            'invalid arguments')

    def test_unobserved_port_and_unlisted_domain(self):
        send = Mock(side_effect=[
            request(call('port_detail', {'host': '100.64.0.4', 'port': 443}),
                    call('feed_lookup', {'domain': 'github.com'}, 'call_2')),
            (FINAL, 'stop'),
        ])
        self.context.complete(send, self.payload)
        results = [json.loads(message['content']) for message in send.call_args.args[0]['messages']
                   if message['role'] == 'tool']
        self.assertEqual(results, [
            {'host': '100.64.0.4', 'port': 443, 'observed_open': None},
            {'domain': 'github.com', 'status': 'clean', 'coverage': None},
        ])
