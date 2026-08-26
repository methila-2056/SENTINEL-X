"""Extended tests for network address classification (boundaries, loopback, edge cases)."""

import pytest

from sentinel_x.common.netutil import is_internal_ip


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        # IPv4 loopback — not RFC1918 (treated as external by this util)
        ("127.0.0.1", False),
        ("127.255.255.255", False),
        # 172.16-31 exact boundaries
        ("172.15.255.255", False),
        ("172.16.0.0", True),
        ("172.31.255.255", True),
        ("172.32.0.0", False),
        # 10.x boundaries
        ("9.255.255.255", False),
        ("10.0.0.0", True),
        ("10.255.255.255", True),
        ("11.0.0.0", False),
        # 192.168 boundary
        ("192.167.255.255", False),
        ("192.168.0.0", True),
        ("192.168.255.255", True),
        ("192.169.0.0", False),
        # Various public IPs
        ("8.8.4.4", False),
        ("1.1.1.1", False),
        ("203.0.113.1", False),
        ("198.51.100.1", False),
    ],
)
def test_ip_classification(ip: str, expected: bool) -> None:
    assert is_internal_ip(ip) is expected
