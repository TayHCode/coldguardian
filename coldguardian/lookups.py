import ipaddress
import json
import logging
import re

from .feeds import domain_key
from .model import unique_object
from .report import model_observation


LOGGER = logging.getLogger(__name__)
MAX_CALLS = 3
HOST = {'type': 'string', 'description': 'An approved IP address or configured host name'}
PORT = {'type': 'integer', 'minimum': 1, 'maximum': 65535}
DOMAIN = {'type': 'string', 'description': 'A DNS domain, without a scheme, port or path'}
TOOLS = [
    {'type': 'function', 'function': {
        'name': name, 'description': description,
        'parameters': {'type': 'object', 'properties': properties,
                       'required': list(properties), 'additionalProperties': False},
    }}
    for name, description, properties in (
        ('baseline_history', 'Read the approved and previously observed open ports', {'host': HOST}),
        ('port_detail', 'Read details of a TCP port from the current scan', {'host': HOST, 'port': PORT}),
        ('feed_lookup', 'Check an exact domain against the local feed cache', {'domain': DOMAIN}),
    )
]
ARGUMENTS = {tool['function']['name']: set(tool['function']['parameters']['required']) for tool in TOOLS}
CALL_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')


class LookupRefused(ValueError):
    pass


def parse_call(call):
    if not isinstance(call, dict) or call.get('type') != 'function':
        raise LookupRefused('invalid tool call')
    call_id, function = call.get('id'), call.get('function')
    if not isinstance(call_id, str) or not CALL_ID.fullmatch(call_id) or not isinstance(function, dict):
        raise LookupRefused('invalid tool call')
    name, arguments = function.get('name'), function.get('arguments')
    if not isinstance(name, str) or name not in ARGUMENTS:
        raise LookupRefused('unknown tool')
    if not isinstance(arguments, str) or len(arguments) > 1024:
        raise LookupRefused('invalid arguments')
    try:
        args = json.loads(arguments, object_pairs_hook=unique_object)
    except (ValueError, RecursionError):
        raise LookupRefused('invalid arguments') from None
    if not isinstance(args, dict) or args.keys() != ARGUMENTS[name]:
        raise LookupRefused('invalid arguments')
    return call_id, name, args


class LookupContext:
    def __init__(self, config, approved, previous, current, scan_findings, domains, feed_warning):
        self.hosts = config['hosts']
        self.peers = set(self.hosts.values()) | set(config.get('tailscale_peers', ()))
        self.networks = (config['_lan'], *map(ipaddress.ip_network, config.get('wireguard_subnets', ())))
        self.approved = approved
        self.previous = previous
        self.current = current
        self.services = {(f['ip'], f['port']): f for f in scan_findings if f['category'] == 'service'}
        self.domains = domains
        self.feed_warning = feed_warning

    def _host(self, value):
        if not isinstance(value, str) or len(value) > 63 or '%' in value:
            raise LookupRefused('invalid host')
        try:
            address = ipaddress.ip_address(self.hosts.get(value, value))
        except ValueError:
            raise LookupRefused('invalid host') from None
        if str(address) in self.peers or any(
            address in network and (network.version != 4 or network.prefixlen >= 31
                                    or address not in (network.network_address, network.broadcast_address))
            for network in self.networks
        ):
            return str(address)
        raise LookupRefused('host outside scope')

    def _lookup(self, name, args):
        if name == 'feed_lookup':
            domain = args['domain']
            if not isinstance(domain, str) or len(domain) > 254 or not domain.isascii() or not (domain := domain_key(domain)):
                raise LookupRefused('invalid domain')
            status = 'bad' if domain in self.domains else ('unknown' if self.feed_warning else 'clean')
            return {'domain': domain, 'status': status, 'coverage': self.feed_warning}

        host = self._host(args['host'])
        if name == 'baseline_history':
            return {'host': host, 'approved_ports': self.approved.get(host),
                    'previous_ports': self.previous.get(host)}

        port = args['port']
        if type(port) is not int or not 1 <= port <= 65535:
            raise LookupRefused('invalid port')
        observed = port in self.current.get(host, ())
        result = {'host': host, 'port': port, 'observed_open': True if observed else None}
        if observed and (service := self.services.get((host, port))):
            observation = model_observation(service)
            result.update({key: observation[key] for key in ('service', 'auth_methods') if key in observation})
        return result

    def complete(self, send, payload):
        messages = list(payload['messages'])
        seen = set()
        try:
            while True:
                message, reason = send(dict(payload, messages=messages, tools=TOOLS))
                calls = message.get('tool_calls')
                if message.get('function_call') is not None:
                    raise LookupRefused('invalid tool call')
                if reason == 'stop' and (calls is None or calls == []):
                    return message
                if calls is None or calls == []:
                    if reason == 'tool_calls':
                        raise LookupRefused('invalid tool call')
                    raise ValueError('invalid finish reason')
                if reason != 'tool_calls' or not isinstance(calls, list):
                    raise LookupRefused('invalid tool call')
                if len(calls) > MAX_CALLS - len(seen):
                    raise LookupRefused('call limit exceeded')
                accepted, results = [], []
                for call in calls:
                    call_id, name, args = parse_call(call)
                    if call_id in seen:
                        raise LookupRefused('duplicate call ID')
                    seen.add(call_id)
                    result = self._lookup(name, args)
                    accepted.append({'id': call_id, 'type': 'function', 'function': {
                        'name': name, 'arguments': json.dumps(args),
                    }})
                    results.append({'role': 'tool', 'tool_call_id': call_id, 'content': json.dumps(result)})
                messages = [*messages, {'role': 'assistant', 'tool_calls': accepted}, *results]
        except LookupRefused as error:
            LOGGER.warning('Model lookup refused: %s', error)
            raise
