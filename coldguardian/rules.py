import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


RULES_PATH = Path(__file__).with_name('risky_services.json')
RULE_ID = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
RULE_KEYS = {'id', 'title', 'reason', 'match', 'unless'}
CLAUSE_KEYS = {'port', 'service', 'product', 'tunnel', 'fingerprint', 'script'}


def _text(value):
    return isinstance(value, str) and value.strip() == value and value != ''


def _strings(value, allow_empty=False):
    return isinstance(value, list) and value != [] and all(isinstance(v, str) and (allow_empty or _text(v)) for v in value)


def _script_condition(value):
    return (isinstance(value, dict) and set(value) <= {'id', 'table', 'elem'} and _text(value.get('id'))
            and ('table' not in value or _text(value['table']))
            and ('elem' not in value or ('table' in value and _strings(value['elem']))))


def _clause(value):
    if not isinstance(value, dict) or not value or not set(value) <= CLAUSE_KEYS:
        return False
    ports = value.get('port', [1])
    return (isinstance(ports, list) and ports != [] and all(type(p) is int and 1 <= p <= 65535 for p in ports)
            and all(_strings(value[k], allow_empty=True) for k in ('service', 'tunnel') if k in value)
            and all(_strings(value[k]) for k in ('product', 'fingerprint') if k in value)
            and ('script' not in value or _script_condition(value['script'])))


def load_rules(path=RULES_PATH):
    rules = json.loads(Path(path).read_text(encoding='utf-8'))
    if not isinstance(rules, list) or not rules:
        raise ValueError('risky services must be a non-empty list of rules')
    seen = set()
    for rule in rules:
        if not isinstance(rule, dict) or not {'id', 'title', 'reason', 'match'} <= set(rule) <= RULE_KEYS:
            raise ValueError('each risky service rule needs id, title, reason and match, and nothing else but unless')
        if not isinstance(rule['id'], str) or not RULE_ID.fullmatch(rule['id']) or rule['id'] in seen:
            raise ValueError(f'invalid or duplicate rule id: {rule["id"]!r}')
        seen.add(rule['id'])
        if not _text(rule['title']) or not _text(rule['reason']):
            raise ValueError(f'rule {rule["id"]} needs a title and a plain reason')
        if not isinstance(rule['match'], list) or not rule['match'] or not all(_clause(c) for c in rule['match']):
            raise ValueError(f'rule {rule["id"]} has an invalid match clause')
        unless = rule.get('unless', [])
        if not isinstance(unless, list) or not all(_script_condition(c) for c in unless):
            raise ValueError(f'rule {rule["id"]} has an invalid unless condition')
    return rules


def open_tcp_ports(xml):
    root = ET.fromstring(xml)
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            address = host.find("address[@addrtype='ipv6']")
        if address is None:
            raise ValueError('host without an IP address')
        for port in host.findall('ports/port'):
            state = port.find('state')
            if port.get('protocol') != 'tcp' or state is None or state.get('state') != 'open':
                continue
            service = port.find('service')
            service = {} if service is None else service.attrib
            yield {
                'ip': address.get('addr'),
                'port': int(port.get('portid')),
                'method': service.get('method'),
                'service': service.get('name', '').lower(),
                'product': service.get('product', ''),
                'tunnel': service.get('tunnel', '').lower(),
                'fingerprint': service.get('servicefp', '').replace('\nSF:', '').replace('\\x20', ' '),
                'scripts': {s.get('id'): _tables(s) for s in port.findall('script')},
            }


def _tables(script):
    return {table.get('key', ''): [e.text or '' for e in table.findall('elem')] for table in script.findall('table')}


def _script_hit(condition, scripts):
    tables = scripts.get(condition['id'])
    if tables is None or 'table' not in condition:
        return tables is not None
    elems = tables.get(condition['table'])
    wanted = {e.lower() for e in condition.get('elem', [])}
    return elems is not None and (not wanted or bool(wanted & {e.lower() for e in elems}))


def _clause_hit(clause, seen):
    if ('service' in clause or 'product' in clause) and seen['method'] != 'probed':
        return False
    return (seen['port'] in clause.get('port', [seen['port']])
            and seen['service'] in clause.get('service', [seen['service']])
            and seen['tunnel'] in clause.get('tunnel', [seen['tunnel']])
            and ('product' not in clause or any(p.lower() in seen['product'].lower() for p in clause['product']))
            and ('fingerprint' not in clause or any(f in seen['fingerprint'] for f in clause['fingerprint']))
            and ('script' not in clause or _script_hit(clause['script'], seen['scripts'])))


def check(xml, rules=None):
    rules = load_rules() if rules is None else rules
    findings = []
    for seen in open_tcp_ports(xml):
        matches = [
            rule for rule in rules
            if any(_clause_hit(clause, seen) for clause in rule['match'])
            and not any(_script_hit(exception, seen['scripts']) for exception in rule.get('unless', []))
        ]
        ollama_matched = any(rule['id'] == 'ollama' for rule in matches)
        for rule in matches:
            if ollama_matched and rule['id'] == 'model-server':
                continue
            findings.append({
                'category': 'risky_service',
                'rule': rule['id'],
                'title': rule['title'],
                'reason': rule['reason'],
                'ip': seen['ip'],
                'port': seen['port'],
                'service': seen['service'],
                'product': seen['product'],
                'evidence_id': f'{seen["ip"]}:{seen["port"]}/tcp',
            })
    return findings
