"""Tests for network address classification."""

import pytest

from sentinel_x.common.netutil import is_internal_ip


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("192.168.1.50", True),
    ],
)
def test_rfc1918_internal(ip: str, expected: bool) -> None:
    assert is_internal_ip(ip) is expected


@pytest.mark.parametrize(
    "ip",
    [
        "172.32.0.1",  # outside 172.16-31: public
        "172.15.255.255",
        "172.1.2.3",
        "8.8.8.8",
        "185.220.101.5",
        "192.169.0.1",  # just outside 192.168/16
        "9.9.9.9",
    ],
)
def test_public_addresses_are_external(ip: str) -> None:
    assert is_internal_ip(ip) is False


def test_ipv6_loopback_not_internal_v4() -> None:
    assert is_internal_ip("::1") is False


@pytest.mark.parametrize("bad", [None, "", "unknown", "not-an-ip", "999.1.1.1"])
def test_malformed_values_are_not_internal(bad: str | None) -> None:
    assert is_internal_ip(bad) is False
