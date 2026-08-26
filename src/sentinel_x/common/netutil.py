"""Network address classification helpers."""

import ipaddress

_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def is_internal_ip(ip: str | None) -> bool:
    """True only for RFC 1918 private IPv4 addresses.

    The previous string-prefix checks treated every 172.x address as
    internal; RFC 1918 reserves 172.16.0.0/12 (i.e. 172.16-31), so public
    hosts such as 172.32.1.1 or 172.1.2.3 were misclassified.
    Malformed, empty, IPv6 and public addresses return False.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return addr.version == 4 and any(addr in net for net in _INTERNAL_NETWORKS)
