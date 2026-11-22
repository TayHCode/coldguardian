import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from coldguardian import rules


FIXTURES = Path(__file__).parent / 'fixtures' / 'risky_services'
POSITIVE = sorted((FIXTURES / 'positive').glob('*.xml'))
NEGATIVE = sorted((FIXTURES / 'negative').glob('*.xml'))
REQUIRED = {'telnet', 'ftp', 'smb', 'rdp', 'vnc', 'docker-api', 'redis', 'mongodb', 'elasticsearch', 'ollama', 'model-server', 'ssh-password'}


def no_network(*args, **kwargs):
    raise AssertionError('risky-service rules must not run programs or open sockets')


class RiskyServiceRulesTest(unittest.TestCase):
    def setUp(self):
        self.rules = rules.load_rules()
        patches = [mock.patch.object(socket, 'socket', no_network), mock.patch.object(socket, 'create_connection', no_network),
                   mock.patch.object(subprocess, 'run', no_network), mock.patch.object(subprocess, 'Popen', no_network)]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def test_plan_lists_every_required_rule_with_a_plain_reason(self):
        self.assertEqual({r['id'] for r in self.rules}, REQUIRED)
        for rule in self.rules:
            self.assertGreaterEqual(len(rule['reason'].split()), 10, rule['id'])

    def test_each_rule_has_one_fixture_that_fires_only_that_rule(self):
        self.assertEqual({p.stem for p in POSITIVE}, REQUIRED)
        for path in POSITIVE:
            with self.subTest(fixture=path.name):
                findings = rules.check(path.read_text(), self.rules)
                self.assertEqual([f['rule'] for f in findings], [path.stem])
                rule = next(r for r in self.rules if r['id'] == path.stem)
                self.assertEqual(findings[0]['reason'], rule['reason'])
                self.assertEqual(findings[0]['category'], 'risky_service')
                self.assertEqual(findings[0]['evidence_id'], f"{findings[0]['ip']}:{findings[0]['port']}/tcp")

    def test_hard_negatives_fire_nothing(self):
        self.assertGreaterEqual(len(NEGATIVE), 10)
        for path in NEGATIVE:
            with self.subTest(fixture=path.name):
                self.assertEqual(rules.check(path.read_text(), self.rules), [])

    def test_model_list_requires_success_on_the_exact_path(self):
        xml = (FIXTURES / 'positive' / 'model-server.xml').read_text()
        cases = [
            ('key="/v1/models"', 'key="/other/v1/models"'),
            ('<elem>200 model list</elem>', '<elem>401 model list</elem>'),
            ('<elem>200 model list</elem>', '<elem>200 other response</elem>'),
        ]
        for before, after in cases:
            with self.subTest(evidence=after):
                self.assertEqual(rules.check(xml.replace(before, after), self.rules), [])

    def test_model_list_rule_agrees_with_packaged_nmap_script(self):
        rule = next(rule for rule in self.rules if rule['id'] == 'model-server')
        condition = rule['match'][0]['script']
        script = rules.RULES_PATH.with_name(f"{condition['id']}.nse").read_text()
        marker, = condition['elem']
        self.assertIn(f'local path = "{condition["table"]}"', script)
        self.assertIn(f'return {{ [path] = {{ "{marker}" }} }}', script)

    def test_ollama_finding_takes_precedence_over_generic_model_list(self):
        xml = (FIXTURES / 'positive' / 'model-server.xml').read_text()
        for evidence in ('product="Ollama"', 'servicefp="Ollama is running"'):
            with self.subTest(evidence=evidence):
                ollama_xml = xml.replace('name="http"', f'name="http" {evidence}', 1)
                self.assertEqual([finding['rule'] for finding in rules.check(ollama_xml, self.rules)], ['ollama'])

    def test_elasticsearch_probe_identification_does_not_imply_public_access(self):
        xml = (FIXTURES / 'positive' / 'elasticsearch.xml').read_text()
        xml = xml.replace('version="8.11.1"', 'version="7.0 or later" extrainfo="Shield plugin; realm: security"')
        finding, = rules.check(xml, self.rules)
        self.assertEqual(finding['rule'], 'elasticsearch')
        self.assertEqual(finding['reason'], 'Elasticsearch stores and searches data. If access is unrestricted, people who can reach this service may be able to read or delete its data.')

    def test_finding_names_host_port_and_service(self):
        finding, = rules.check((FIXTURES / 'positive' / 'ssh-password.xml').read_text(), self.rules)
        self.assertEqual((finding['ip'], finding['port'], finding['service'], finding['product']), ('10.99.0.21', 22, 'ssh', 'OpenSSH'))

    def test_default_rules_come_from_the_data_file(self):
        self.assertEqual(rules.check((FIXTURES / 'positive' / 'telnet.xml').read_text())[0]['rule'], 'telnet')

    def test_host_without_an_address_is_rejected(self):
        xml = '<nmaprun><host><status state="up"/><ports><port protocol="tcp" portid="23"><state state="open"/></port></ports></host></nmaprun>'
        with self.assertRaises(ValueError):
            rules.check(xml, self.rules)

    def test_invalid_rule_files_are_rejected(self):
        good = {'id': 'telnet', 'title': 'Telnet is open', 'reason': 'Plain words.', 'match': [{'service': ['telnet']}]}
        bad = [
            [],
            [dict(good, extra=True)],
            [good, good],
            [dict(good, id='Telnet!')],
            [dict(good, reason='')],
            [dict(good, match=[])],
            [dict(good, match=[{}])],
            [dict(good, match=[{'servce': ['telnet']}])],
            [dict(good, match=[{'port': [0]}])],
            [dict(good, match=[{'port': [True]}])],
            [dict(good, match=[{'port': '23'}])],
            [dict(good, match=[{'product': ['']}])],
            [dict(good, match=[{'script': {'id': 'ssh-auth-methods', 'contains': 'password'}}])],
            [dict(good, unless=[{'contains': ['401']}])],
            [dict(good, match=[{'script': {'id': 'ssh-auth-methods', 'elem': ['password']}}])],
            [dict(good, match=[{'fingerprint': []}])],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'rules.json'
            path.write_text(json.dumps([good]))
            self.assertEqual(rules.load_rules(path), [good])
            for data in bad:
                with self.subTest(data=data):
                    path.write_text(json.dumps(data))
                    with self.assertRaises(ValueError):
                        rules.load_rules(path)


if __name__ == '__main__':
    unittest.main()
