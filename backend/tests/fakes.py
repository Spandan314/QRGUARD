"""Fake DNS, HTTP and threat-intel implementations so tests never touch the network."""

from __future__ import annotations

import ipaddress

from app.analyzers.redirect_resolver import (
    FetchConnectionError,
    FetchRequest,
    FetchResponse,
    FetchTimeout,
    FetchTLSError,
)
from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus
from app.utils.net_safety import DNSResolutionError, DNSTimeoutError

PUBLIC_IP = "93.184.215.14"  # any public address; nothing is ever contacted


class FakeResolver:
    """Maps hostnames to IP lists (or to an exception to raise). Unknown hosts -> public IP."""

    def __init__(self, table: dict[str, list[str] | Exception] | None = None) -> None:
        self.table = table or {}
        self.calls: list[str] = []

    def __call__(self, host: str, port: int, timeout: float):
        self.calls.append(host)
        answer = self.table.get(host, [PUBLIC_IP])
        if isinstance(answer, Exception):
            raise answer
        return [ipaddress.ip_address(a) for a in answer]


class FakeFetcher:
    """Maps "scheme://host/path?query" to (status, location) or an exception."""

    def __init__(self, routes: dict[str, tuple[int, str | None] | Exception] | None = None):
        self.routes = routes or {}
        self.requests: list[FetchRequest] = []

    def __call__(self, request: FetchRequest) -> FetchResponse:
        self.requests.append(request)
        key = f"{request.scheme}://{request.host}{request.target}"
        answer = self.routes.get(key, (200, None))
        if isinstance(answer, Exception):
            raise answer
        return FetchResponse(*answer)


def redirect_loop(host: str, count: int) -> dict[str, tuple[int, str | None]]:
    """/0 -> /1 -> ... -> /count, each a 302."""
    return {f"https://{host}/{i}": (302, f"/{i + 1}") for i in range(count)}


class FakeProvider(ThreatIntelProvider):
    def __init__(self, name: str, status: TIStatus, threat_type: str | None = None) -> None:
        self.name = name
        self.status = status
        self.threat_type = threat_type
        self.checked: list[str] = []

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        self.checked.append(normalized_url)
        return ProviderResult(self.name, self.status, self.threat_type)


class BrokenProvider(ThreatIntelProvider):
    name = "broken"

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        raise RuntimeError("provider crashed")


__all__ = [
    "BrokenProvider",
    "DNSResolutionError",
    "DNSTimeoutError",
    "FakeFetcher",
    "FakeProvider",
    "FakeResolver",
    "FetchConnectionError",
    "FetchTLSError",
    "FetchTimeout",
    "PUBLIC_IP",
    "redirect_loop",
]
