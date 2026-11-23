import re
from urllib.parse import urlsplit

from .scope import private_address, usable_address


def valid_topic(topic):
    return isinstance(topic, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', topic) is not None


def validate_ntfy(target):
    if not isinstance(target, dict) or set(target) not in ({'server', 'topic'}, {'server', 'topic', 'detail'}) or not valid_topic(target['topic']):
        raise ValueError('ntfy needs a server URL and a topic of 1–64 letters, digits, underscores, or hyphens')
    if target.get('detail', 'full') not in ('full', 'blank'):
        raise ValueError('ntfy detail must be full or blank')
    server = target['server']
    try:
        if not isinstance(server, str) or not server.isascii() or re.search(r'[\s\x00-\x1f\x7f\\?#]', server):
            raise ValueError
        parsed = urlsplit(server)
        authority = r'(?:[A-Za-z0-9.-]+|\[[A-Fa-f0-9:]+\])(?::[0-9]+)?'
        if (parsed.scheme not in ('http', 'https') or not re.fullmatch(authority, parsed.netloc)
                or parsed.port == 0):
            raise ValueError
    except ValueError:
        raise ValueError('ntfy server must be an HTTP(S) URL without credentials, a query, or a fragment') from None
    return dict(target, server=server.rstrip('/'))


def upnp_endpoint(settings, lan):
    if not isinstance(settings, dict) or set(settings) - {'control_url', 'service'}:
        raise ValueError('upnp requires a router control_url')
    url = settings.get('control_url')
    if not isinstance(url, str) or not re.fullmatch(r'http://[0-9.]+(?::[0-9]+)?/[A-Za-z0-9._~/%-]+', url):
        raise ValueError('upnp control_url must be a LAN IPv4 HTTP URL with a control path')
    parts = urlsplit(url)
    if parts.port == 0 or not usable_address(private_address(parts.hostname, 'upnp'), lan):
        raise ValueError('upnp router must be in lan_cidr')
    service = settings.get('service', 'WANIPConnection:1')
    if service not in ('WANIPConnection:1', 'WANIPConnection:2', 'WANPPPConnection:1'):
        raise ValueError('invalid UPnP WAN connection service')
    return parts, 'urn:schemas-upnp-org:service:' + service
