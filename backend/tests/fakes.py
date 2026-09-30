"""Fake DNS, HTTP and threat-intel implementations so tests never touch the network."""

from __future__ import annotations

import ipaddress

from app.analyzers.ocr import OcrResult
from app.analyzers.redirect_resolver import (
    FetchConnectionError,
    FetchRequest,
    FetchResponse,
    FetchTimeout,
    FetchTLSError,
)
from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus
from app.threat_intelligence.http import HttpResponse, TIHttpError
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


class FakeOcrEngine:
    """Returns fixed text (or raises a given error) instead of running Tesseract."""

    name = "fake-ocr"

    def __init__(
        self,
        text: str = "",
        confidence: float | None = 95.0,
        error: Exception | None = None,
        available: bool = True,
    ) -> None:
        self.text = text
        self.confidence = confidence
        self.error = error
        self._available = available
        self.calls = 0

    def available(self) -> bool:
        return self._available

    def extract(self, image) -> OcrResult:
        self.calls += 1
        if self.error is not None:
            raise self.error
        words = len(self.text.split())
        return OcrResult(self.text, self.confidence if words else None, words, self.name)


__all__ = [
    "FakeOcrEngine",
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


class FakeHttp:
    """Stands in for the threat-intel HTTP client: returns canned responses, records requests."""

    def __init__(self, status: int = 200, data=None, error: bool = False) -> None:
        self.status = status
        self.data = data
        self.error = error
        self.requests: list[dict] = []

    def request(self, method, url, *, headers=None, body=None, timeout):
        self.requests.append(
            {"method": method, "url": url, "headers": headers or {}, "body": body or b""}
        )
        if self.error:
            raise TIHttpError("network error")
        return HttpResponse(self.status, self.data)


class SlowProvider(ThreatIntelProvider):
    """Answers only after `delay` seconds (to test the overall time budget)."""

    name = "slow"

    def __init__(self, delay: float) -> None:
        self.delay = delay

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        import time

        time.sleep(self.delay)
        return ProviderResult(self.name, TIStatus.LISTED, "phishing")
