import re
from urllib.parse import urlsplit


def valid_topic(topic):
    return isinstance(topic, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', topic) is not None


def validate_ntfy(target):
    if not isinstance(target, dict) or set(target) != {'server', 'topic'} or not valid_topic(target['topic']):
        raise ValueError('ntfy needs a server URL and a topic of 1–64 letters, digits, underscores, or hyphens')
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
