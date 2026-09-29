import ipaddress
import socket
import time

import pytest

from app.utils import net_safety
from app.utils.net_safety import (
    DNSResolutionError,
    DNSTimeoutError,
    is_public_ip,
    parse_ip_literal,
    resolve_host,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.255.255.254",  # loopback 127.0.0.0/8
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",  # private
        "169.254.169.254",  # link-local / cloud metadata
        "0.0.0.0",  # noqa: S104 (address under test, not a bind)
        "100.64.0.1",
        "198.18.0.1",  # unspecified, CGNAT, benchmarking
        "224.0.0.1",
        "239.255.255.250",  # multicast
        "240.0.0.1",
        "255.255.255.255",  # reserved / broadcast
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",  # IPv6 special ranges
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",  # IPv4-mapped
        "2002:7f00:1::1",  # 6to4 wrapping 127.0.0.1
        "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1
        "not-an-ip",
    ],
)
def test_blocked_addresses(address):
    assert is_public_ip(address) is False


@pytest.mark.parametrize("address", ["8.8.8.8", "93.184.215.14", "2606:4700:4700::1111"])
def test_public_addresses(address):
    assert is_public_ip(address) is True


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("3232235777", "192.168.1.1"),
        ("0xC0A80101", "192.168.1.1"),
        ("0300.0250.1.1", "192.168.1.1"),
        ("10.1", "10.0.0.1"),
        ("[::1]", "::1"),
    ],
)
def test_parse_disguised_ip(host, expected):
    assert parse_ip_literal(host) == ipaddress.ip_address(expected)


@pytest.mark.parametrize("host", ["example.com", "1.2.3.4.5", "256.1.1.1", "08.1.1.1", "0x.zz"])
def test_non_ip_hosts(host):
    assert parse_ip_literal(host) is None


def test_resolve_host_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("no such host")

    monkeypatch.setattr(net_safety.socket, "getaddrinfo", fail)
    with pytest.raises(DNSResolutionError):
        resolve_host("does-not-exist.example", 443, timeout=1)


def test_resolve_host_timeout(monkeypatch):
    def slow(*args, **kwargs):
        time.sleep(0.5)
        return []

    monkeypatch.setattr(net_safety.socket, "getaddrinfo", slow)
    with pytest.raises(DNSTimeoutError):
        resolve_host("slow.example", 443, timeout=0.05)


def test_resolve_host_returns_unique_addresses(monkeypatch):
    info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.215.14", 443))] * 2
    monkeypatch.setattr(net_safety.socket, "getaddrinfo", lambda *a, **k: info)
    assert resolve_host("example.com", 443, timeout=1) == [ipaddress.ip_address("93.184.215.14")]
