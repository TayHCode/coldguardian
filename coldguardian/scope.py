import ipaddress


CGNAT = ipaddress.ip_network('100.64.0.0/10')
TAILSCALE_RANGES = (CGNAT, ipaddress.ip_network('fd7a:115c:a1e0::/48'))
PRIVATE_RANGES = (*map(ipaddress.ip_network, ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fc00::/7')), CGNAT)
PRIVATE_SCOPE = 'private scope (RFC 1918, CGNAT 100.64.0.0/10, or IPv6 ULA fc00::/7)'
MIN_PREFIX_LENGTH = {4: 16, 6: 64}


class ScopeError(ValueError):
    pass


def is_private_network(network):
    return any(network.version == allowed.version and network.subnet_of(allowed) for allowed in PRIVATE_RANGES)


def usable_address(address, network):
    return address in network and (
        network.version != 4 or network.prefixlen >= 31
        or address not in (network.network_address, network.broadcast_address)
    )


def check_snapshot_scope(c, hosts):
    exact = set(c['hosts'].values()) | c['_tailscale_ipv4']
    networks = (c['_lan'], *c['_wireguard_ipv4'])
    for ip in hosts - exact:
        address = ipaddress.ip_address(ip)
        if str(address) != ip or not any(usable_address(address, network) for network in networks):
            raise ValueError('target outside approved scope')


def private_network(value, field):
    prefix = value.partition('/')[2] if isinstance(value, str) and '%' not in value else ''
    if not prefix.isascii() or not prefix.isdecimal():
        raise ScopeError(f'{field} must be a CIDR range')
    try:
        network = ipaddress.ip_network(value)
    except ValueError:
        raise ScopeError(f'{field} must be a CIDR range with no host bits') from None
    if not is_private_network(network):
        raise ScopeError(f'{field} must be wholly within {PRIVATE_SCOPE}')
    minimum = MIN_PREFIX_LENGTH[network.version]
    if network.prefixlen < minimum:
        raise ScopeError(f'{field} must have an IPv{network.version} prefix of /{minimum} or longer')
    return network


def private_address(value, field):
    try:
        if not isinstance(value, str) or '%' in value:
            raise ValueError
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ScopeError(f'{field} must contain exact IP addresses') from None
    if not any(address in allowed for allowed in PRIVATE_RANGES):
        raise ScopeError(f'{field} must be within {PRIVATE_SCOPE}')
    return address


def tailscale_address(value, field):
    address = private_address(value, field)
    if not any(address in allowed for allowed in TAILSCALE_RANGES):
        raise ScopeError(f'{field} must use Tailscale address ranges')
    return address
