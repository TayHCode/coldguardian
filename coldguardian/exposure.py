import http.client
import ipaddress
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from contextlib import closing

from .model import unique_object
from .scan import command, finding


SOAP = '{http://schemas.xmlsoap.org/soap/envelope/}'
CONTROL = '{urn:schemas-upnp-org:control-1-0}'
ACTION = 'GetGenericPortMappingEntry'
DNS_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
NODE = re.compile(rf'{DNS_LABEL}(?:\.{DNS_LABEL})*')
STATUS = {
    'upnp': {
        'clear': 'No enabled UPnP IPv4 mappings reported by the configured router.',
        'exposed': 'The configured router reports enabled UPnP IPv4 mappings.',
        'incomplete': 'UPnP IPv4 mapping coverage on the configured router is incomplete.',
    },
    'tailscale_funnel': {
        'clear': 'No Funnel on this node.',
        'exposed': 'Funnel is enabled on this node.',
        'incomplete': 'Funnel coverage on this node is incomplete.',
    },
}


def port_number(text):
    if not isinstance(text, str) or not re.fullmatch('[0-9]{1,5}', text) or not 1 <= int(text) <= 65535:
        raise ValueError('invalid port')
    return int(text)


def mapping_entry(endpoint, index, timeout):
    url, service = endpoint
    body = (f'<s:Envelope xmlns:s="{SOAP[1:-1]}" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            f'<s:Body><u:{ACTION} xmlns:u="{service}"><NewPortMappingIndex>{index}</NewPortMappingIndex>'
            f'</u:{ACTION}></s:Body></s:Envelope>')
    with closing(http.client.HTTPConnection(url.hostname, url.port, timeout=timeout)) as conn:
        conn.request('POST', url.path, body, {'Content-Type': 'text/xml; charset="utf-8"',
                                              'SOAPAction': f'"{service}#{ACTION}"'})
        response = conn.getresponse()
        raw = response.read(65537)
    if len(raw) > 65536 or b'<!DOCTYPE' in raw or b'\x00' in raw:
        raise ValueError('invalid router response')
    root = ET.fromstring(raw.decode('utf-8'))
    if root.tag != SOAP + 'Envelope':
        raise ValueError('invalid SOAP envelope')
    soap_body, = root.findall(SOAP + 'Body')
    result, = soap_body
    if response.status == 500 and result.tag == SOAP + 'Fault':
        error, = result.findall(f'detail/{CONTROL}UPnPError/{CONTROL}errorCode')
        if error.text == '713':
            return None
    if response.status != 200 or result.tag != f'{{{service}}}{ACTION}Response':
        raise ValueError('router enumeration failed')
    if any(len(field) for field in result):
        raise ValueError('invalid mapping fields')
    return unique_object((field.tag, field.text or '') for field in result)


def router_mappings(c):
    deadline = time.monotonic() + 15
    for index in range(65536):
        left = deadline - time.monotonic()
        if left <= 0:
            break
        row = mapping_entry(c['_upnp_endpoint'], index, min(3, left))
        if row is None:
            return
        ip = ipaddress.IPv4Address(row['NewInternalClient'])
        external, internal = port_number(row['NewExternalPort']), port_number(row['NewInternalPort'])
        protocol, enabled = row['NewProtocol'], row['NewEnabled']
        remote = row['NewRemoteHost']
        if remote:
            ipaddress.IPv4Address(remote)
        if (ip.is_multicast or ip.is_unspecified or protocol not in ('TCP', 'UDP')
                or enabled not in ('0', '1', 'true', 'false', 'yes', 'no')):
            raise ValueError('invalid mapping')
        if enabled in ('1', 'true', 'yes'):
            yield finding('upnp_mapping', ip=str(ip), port=external, internal_port=internal, protocol=protocol,
                          **({'remote_ip': remote} if remote else {}))
    raise ValueError('router enumeration incomplete')


def funnel_endpoints(c):
    raw = command(['tailscale', 'funnel', 'status', '--json'], 10)
    if len(raw) > 1024 * 1024:
        raise ValueError('Funnel status too large')
    config = json.loads(raw, object_pairs_hook=unique_object)
    if config is None:
        return
    if not isinstance(config, dict) or not isinstance(config.get('Foreground', {}), dict):
        raise ValueError('invalid Funnel status')
    for scope in [config, *config.get('Foreground', {}).values()]:
        if (not isinstance(scope, dict) or set(scope) - {'AllowFunnel', 'TCP', 'Web', 'Services', 'Foreground'}
                or any(not isinstance(value, dict) for value in scope.values())
                or (scope is not config and 'Foreground' in scope)):
            raise ValueError('invalid Funnel configuration')
        for endpoint, enabled in scope.get('AllowFunnel', {}).items():
            node, _, number = endpoint.rpartition(':')
            port = port_number(number)
            if type(enabled) is not bool or len(node) > 253 or not NODE.fullmatch(node):
                raise ValueError('invalid Funnel endpoint')
            if not enabled:
                continue
            handler = scope.get('TCP', {}).get(number)
            if not isinstance(handler, dict):
                raise ValueError('missing Funnel listener')
            forward = handler.get('TCPForward')
            if forward:
                if not isinstance(forward, str):
                    raise ValueError('invalid Funnel TCP forward')
                target, _, target_port = forward.rpartition(':')
                port_number(target_port)
                if not NODE.fullmatch(target):
                    ipaddress.ip_address(target.removeprefix('[').removesuffix(']'))
            else:
                web = scope.get('Web', {}).get(endpoint)
                if (handler.get('HTTPS') is not True or not isinstance(web, dict)
                        or not isinstance(web.get('Handlers'), dict) or not web['Handlers']
                        or not all(isinstance(h, dict) and any(isinstance(h.get(k), str) and h[k]
                                   for k in ('Proxy', 'Path', 'Text')) for h in web['Handlers'].values())):
                    raise ValueError('missing Funnel service')
            yield finding('tailscale_funnel', node=node.lower(), port=port)


def collect(c, *, excluded=()):
    findings, results = [], {}
    for source, read in (('upnp', router_mappings), ('tailscale_funnel', funnel_endpoints)):
        if not c.get(source):
            continue
        if source == 'upnp' and c['_upnp_endpoint'][0].hostname in excluded:
            results[source] = 'incomplete'
            findings.append(finding('coverage', component=source, ip=c['_upnp_endpoint'][0].hostname))
            continue
        state = 'clear'
        try:
            for item in read(c):
                findings.append(item)
                state = 'exposed'
        except (ValueError, KeyError, OSError, http.client.HTTPException, ET.ParseError,
                subprocess.SubprocessError, RecursionError):
            state = 'incomplete'
            findings.append(finding('coverage', component=source))
        results[source] = state
        findings.append(finding('source_summary', component=source, exposure_status=state))
    return findings, results


def description(item):
    if item['category'] == 'tailscale_funnel':
        return f"Public Funnel on this node at {item.get('node', '?')}:{item.get('port', '?')}"
    restriction = ' from ' + item['remote_ip'] if 'remote_ip' in item else ''
    return (f"Router forwards inbound {item.get('protocol', '?')} port {item.get('port', '?')}{restriction} "
            f"to {item.get('ip', '?')}:{item.get('internal_port', '?')}")
