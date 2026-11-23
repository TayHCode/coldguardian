from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET

from coldguardian import cli, exposure, model, notify, report, scan
from test_retention_churn import DEVICE, LAN, SCANNER


ROUTER = {'control_url': f'http://{SCANNER}:8080/igd/control'}
SERVICE = 'urn:schemas-upnp-org:service:WANIPConnection:1'
ENVELOPE = '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>{}</s:Body></s:Envelope>'
END = ENVELOPE.format('<s:Fault><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">'
                      '<errorCode>713</errorCode></UPnPError></detail></s:Fault>')
ENTRY = ENVELOPE.format(
    f'<u:GetGenericPortMappingEntryResponse xmlns:u="{SERVICE}">'
    '<NewRemoteHost></NewRemoteHost><NewExternalPort>9443</NewExternalPort>'
    f'<NewProtocol>TCP</NewProtocol><NewInternalPort>443</NewInternalPort><NewInternalClient>{DEVICE}</NewInternalClient>'
    '<NewEnabled>1</NewEnabled><NewPortMappingDescription>private description</NewPortMappingDescription>'
    '<NewLeaseDuration>0</NewLeaseDuration></u:GetGenericPortMappingEntryResponse>'
)
ENDPOINT = 'node.example.test:443'
WEB = {'TCP': {'443': {'HTTPS': True}}, 'Web': {ENDPOINT: {'Handlers': {'/': {'Proxy': 'http://localhost:3000'}}}}}


def response(status, body):
    return Mock(status=status, read=Mock(return_value=body.encode()))


class ExposureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.path = self.root / 'settings.json'
        self.settings = dict(lan_cidr=str(LAN), hosts={'scanner': SCANNER}, upnp=ROUTER, tailscale_funnel=True,
                             ports='443', level='low', auth_paths=[], output_dir=str(self.root))
        self.conn = self.enterContext(patch.object(exposure.http.client, 'HTTPConnection')).return_value
        self.proc = self.enterContext(patch('subprocess.run', side_effect=AssertionError('unexpected command')))
        self.enterContext(patch('socket.socket', side_effect=AssertionError('unexpected network access')))
        self.enterContext(patch.object(model, 'chat', side_effect=AssertionError('unexpected model call')))
        self.enterContext(patch.object(cli, 'scan', return_value=({SCANNER: [443]}, [])))
        self.enterContext(patch.object(cli, 'lan_macs', return_value={}))
        self.enterContext(patch.object(cli, 'collect', return_value=({}, [])))
        self.send = self.enterContext(patch.object(notify, 'send', return_value={'status': 'accepted'}))
        self.settings['ntfy'] = {'server': 'https://notify.example', 'topic': 'fixture'}
        report.atomic_json(self.root / 'baseline.json', dict(fingerprint=scan.config(self.settings)['_fingerprint'],
                                                             hosts={SCANNER: [443]}))

    def funnel(self, config):
        self.proc.side_effect = None
        self.proc.return_value.stdout = json.dumps(config).encode()

    def run_cli(self, *args):
        self.path.write_text(json.dumps(self.settings))
        with redirect_stdout(io.StringIO()) as output:
            code = cli.main([*args, '--config', str(self.path)])
        return code, output.getvalue()

    def test_public_exposures_page_at_low_and_distinguish_mapping_changes(self):
        self.funnel({'Foreground': {'session': dict(WEB, AllowFunnel={ENDPOINT: True})}})
        self.conn.getresponse.side_effect = [response(200, ENTRY), response(500, END)] * 2 + [
            response(200, ENTRY.replace('TCP', 'UDP')), response(500, END)]
        for n in range(3):
            code, raw = self.run_cli('scan', '--quick', '--json')
            self.assertEqual(code, 1)
            public = [f for f in json.loads(raw)['findings'] if f.get('delivery_class') == 'hard_page']
            self.assertEqual({f['category'] for f in public}, {'upnp_mapping', 'tailscale_funnel'})
            self.assertNotIn('private description', raw)
            self.assertNotIn('localhost:3000', raw)
            pages = [call for call in self.send.call_args_list if 'mode' not in call.kwargs]
            self.assertEqual(len(pages), (1, 1, 2)[n])
            self.assertIn(DEVICE, ' '.join(pages[-1].args[0]))
        self.assertEqual(self.proc.call_args.args[0], ['tailscale', 'funnel', 'status', '--json'])
        for index, call in enumerate(self.conn.request.call_args_list):
            method, path, body, headers = call.args
            self.assertEqual((method, path, headers['SOAPAction']),
                             ('POST', '/igd/control', f'"{SERVICE}#GetGenericPortMappingEntry"'))
            action, = ET.fromstring(body).find(exposure.SOAP + 'Body')
            self.assertEqual(action.tag, f'{{{SERVICE}}}GetGenericPortMappingEntry')
            field, = action
            self.assertEqual((field.tag, field.text), ('NewPortMappingIndex', str(index % 2)))

    def test_reopened_funnel_pages_after_completed_scan_with_tiers(self):
        del self.settings['upnp']
        self.settings['tiers'] = {'servers': ['scanner'], 'household': 'lan'}
        public = {'TCP': {'443': {'TCPForward': '127.0.0.1:3000'}}, 'AllowFunnel': {ENDPOINT: True}}
        for config, count in [(public, 1), ([], 1), (public, 1), ({}, 1), (public, 2)]:
            self.funnel(config)
            _, raw = self.run_cli('scan', '--quick', '--json')
            if config == public:
                item, = [f for f in json.loads(raw)['findings'] if f['category'] == 'tailscale_funnel']
                self.assertEqual(item['delivery_class'], 'hard_page')
            pages = [call for call in self.send.call_args_list if 'mode' not in call.kwargs]
            self.assertEqual(len(pages), count)

    def test_clear_router_status_is_limited_to_reported_upnp_ipv4_mappings(self):
        del self.settings['tailscale_funnel']
        self.conn.getresponse.return_value = response(500, END)
        self.assertEqual(self.run_cli('scan', '--quick', '--json')[0], 0)
        code, raw = self.run_cli('status', '--json')
        self.assertEqual(code, 0)
        message = json.loads(raw)['exposure']['upnp']['message']
        self.assertEqual(message, 'No enabled UPnP IPv4 mappings reported by the configured router.')
        self.assertNotIn('No enabled port forwards', raw)

    def test_status_and_reports_scope_clean_results_to_this_node(self):
        self.conn.getresponse.return_value = response(500, END)
        self.assertEqual(self.run_cli('status', '--json')[0], 2)
        for config in (None, {}, WEB, dict(WEB, AllowFunnel={ENDPOINT: False})):
            with self.subTest(config=config):
                self.funnel(config)
                code, raw = self.run_cli('scan', '--quick', '--json')
                self.assertEqual(code, 0)
                self.assertIn('No Funnel on this node.', raw)
                self.assertIn('No Funnel on this node.', (self.root / 'latest.md').read_text())
                self.assertIn('No Funnel on this node.', self.run_cli('status')[1])
                code, raw = self.run_cli('status', '--json')
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(raw)['exposure']['tailscale_funnel'],
                                 {'status': 'clear', 'message': 'No Funnel on this node.'})

    def test_partial_mapping_still_pages_and_unreadable_sources_replace_last_success(self):
        self.funnel({})
        self.conn.getresponse.return_value = response(500, END)
        self.assertEqual(self.run_cli('scan', '--quick', '--json')[0], 0)
        self.proc.side_effect = subprocess.CalledProcessError(1, 'tailscale')
        self.conn.getresponse.side_effect = [response(200, ENTRY), TimeoutError()]
        code, raw = self.run_cli('scan', '--deep', '--json')
        self.assertEqual(code, 1)
        findings = json.loads(raw)['findings']
        self.assertTrue(any(f.get('delivery_class') == 'hard_page' for f in findings))
        self.assertEqual({f['component'] for f in findings if f['category'] == 'coverage'},
                         {'tailscale_funnel', 'upnp'})
        code, raw = self.run_cli('status', '--json')
        self.assertEqual(code, 2)
        self.assertEqual({v['status'] for v in json.loads(raw)['exposure'].values()}, {'incomplete'})
        self.assertNotIn('No Funnel', raw)

    def test_malformed_or_unrelated_status_is_incomplete(self):
        del self.settings['upnp']
        for value in ([], {'Error': 'invalid'}, {'AllowFunnel': {ENDPOINT: 'true'}},
                      {'AllowFunnel': {ENDPOINT: True}}, {'AllowFunnel': {'bad\nname:443': True}},
                      dict(WEB, Web={}, AllowFunnel={ENDPOINT: True}), {'Foreground': {'id': []}}):
            with self.subTest(value=value):
                self.funnel(value)
                code, raw = self.run_cli('scan', '--quick', '--json')
                self.assertEqual(code, 2)
                self.assertIn('Funnel coverage on this node is incomplete', raw)
        self.proc.return_value.stdout = b'{"AllowFunnel":{},"AllowFunnel":{}}'
        self.assertEqual(self.run_cli('scan', '--quick', '--json')[0], 2)

    def test_router_requires_exact_response_and_end_fault(self):
        del self.settings['tailscale_funnel']
        for status, body in ((500, END.replace('713', '501')), (500, END.replace('UPnPError', 'Other')),
                             (302, END), (200, END), (200, '<broken'), (200, ENTRY.replace(SERVICE, 'unrelated')),
                             (200, ENTRY.replace('>9443<', '>0<')), (200, ENTRY.replace('>1<', '>other<')),
                             (200, ENTRY.replace('<NewProtocol>', '<NewProtocol>UDP</NewProtocol><NewProtocol>')),
                             (200, '<!DOCTYPE a>' + ENTRY)):
            with self.subTest(status=status, body=body):
                self.conn.getresponse.return_value = response(status, body)
                self.assertEqual(self.run_cli('scan', '--deep', '--json')[0], 2)
        self.conn.getresponse.side_effect = [response(200, ENTRY.replace('>1<', '>0<')), response(500, END)]
        self.assertEqual(self.run_cli('scan', '--deep', '--json')[0], 0)

    def test_disabled_checks_leave_legacy_output_and_baseline_alone(self):
        original = scan.config(self.settings)['_fingerprint']
        del self.settings['upnp']
        self.settings['tailscale_funnel'] = False
        self.assertEqual(scan.config(self.settings)['_fingerprint'], original)
        self.assertEqual(self.run_cli('scan', '--quick', '--json')[0], 0)
        self.assertNotIn('exposure', json.loads(self.run_cli('status', '--json')[1]))
        self.proc.assert_not_called()
        self.conn.request.assert_not_called()

    def test_router_endpoint_is_bound_to_the_lan(self):
        for url in ('http://example.test/control', 'http://203.0.113.1/control', f'http://{SCANNER}/x?q=y',
                    f'http://u@{SCANNER}/x', f'http://{SCANNER}:0/x', f'http://{LAN.broadcast_address}/x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                scan.config(dict(self.settings, upnp={'control_url': url}))
        with self.assertRaises(ValueError):
            scan.config(dict(self.settings, tailscale_funnel='true'))
