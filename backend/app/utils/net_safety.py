"""Network safety helpers used to prevent SSRF (Server-Side Request Forgery).

SSRF happens when an attacker makes OUR server send requests to places it should
never reach: localhost, the cloud metadata service (169.254.169.254), or other
machines on a private network. Every address the backend is about to contact
must pass ``is_public_ip``.
"""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Extra IPv4 ranges we block even though Python may consider some of them "global".
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "this network"
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT (shared address space)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 (can embed private IPv4)
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
]


class DNSResolutionError(Exception):
    """The hostname does not exist or DNS did not answer."""


class DNSTimeoutError(DNSResolutionError):
    """DNS did not answer in time."""


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return an IPv4 address hidden inside an IPv6 one (mapped, 6to4 or Teredo)."""
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    return None


def is_public_ip(ip: IPAddress | str) -> bool:
    """True only for globally routable unicast addresses that are safe to contact.

    Blocks loopback (127.0.0.0/8, ::1), private (10/8, 172.16/12, 192.168/16, fc00::/7),
    link-local (169.254/16 incl. cloud metadata, fe80::/10), multicast, reserved,
    unspecified (0.0.0.0, ::), carrier-grade NAT, and IPv4 addresses hidden inside IPv6.
    """
    try:
        address = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address):
        inner = _embedded_ipv4(address)
        if inner is not None and not is_public_ip(inner):
            return False

    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    ):
        return False
    return not any(address in network for network in _EXTRA_BLOCKED_NETWORKS)


def parse_ip_literal(host: str) -> IPAddress | None:
    """Parse a host that is an IP address, including disguised IPv4 forms.

    Browsers accept IPv4 written as a single number (``3232235777``), in hex
    (``0x7f.0.0.1``), in octal (``0177.0.0.1``) or with fewer than 4 parts
    (``127.1``). Attackers use these to hide an address, so we decode them the
    same way a browser would (WHATWG URL standard).
    """
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    return _parse_whatwg_ipv4(host)


def _parse_ipv4_number(part: str) -> int | None:
    if part == "":
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part[1:], 8)
        return int(part, 10)
    except ValueError:
        return None


def _parse_whatwg_ipv4(host: str) -> ipaddress.IPv4Address | None:
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts.pop()  # a trailing dot is allowed
    if not 1 <= len(parts) <= 4:
        return None
    numbers = [_parse_ipv4_number(part) for part in parts]
    if any(number is None for number in numbers):
        return None
    values: list[int] = [n for n in numbers if n is not None]
    if any(value > 255 for value in values[:-1]):
        return None
    if values[-1] >= 256 ** (5 - len(values)):
        return None
    ipv4 = values[-1]
    for index, value in enumerate(values[:-1]):
        ipv4 += value * 256 ** (3 - index)
    return ipaddress.IPv4Address(ipv4)


def is_disguised_ipv4(host: str, ip: IPAddress) -> bool:
    """True when the host spells an IPv4 address in a non-standard way."""
    return isinstance(ip, ipaddress.IPv4Address) and host.rstrip(".") != str(ip)


# A small shared pool lets us put a timeout on getaddrinfo(), which has none of its own.
_DNS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="qrguard-dns")


def resolve_host(host: str, port: int, timeout: float) -> list[IPAddress]:
    """Resolve ``host`` to all of its IP addresses (A and AAAA), with a timeout."""

    def _lookup() -> list[IPAddress]:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[IPAddress] = []
        for info in infos:
            address = ipaddress.ip_address(info[4][0].split("%")[0])  # drop IPv6 scope id
            if address not in addresses:
                addresses.append(address)
        return addresses

    future = _DNS_POOL.submit(_lookup)
    try:
        addresses = future.result(timeout=timeout)
    except FutureTimeout as exc:
        raise DNSTimeoutError(f"DNS lookup timed out after {timeout}s") from exc
    except (socket.gaierror, UnicodeError, OSError) as exc:
        raise DNSResolutionError("DNS lookup failed") from exc
    if not addresses:
        raise DNSResolutionError("DNS returned no addresses")
    return addresses
