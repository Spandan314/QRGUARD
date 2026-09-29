"""Redirect checker tests. DNS and HTTP are faked; only the last test uses a real local
HTTP server, calling the low-level fetcher directly to prove it never reads the body."""

import http.server
import ipaddress
import threading
import time

import pytest

from app.analyzers import redirect_resolver as rr
from app.analyzers.redirect_resolver import FetchRequest, RedirectSettings, resolve_redirects
from tests.fakes import (
    DNSResolutionError,
    DNSTimeoutError,
    FakeFetcher,
    FakeResolver,
    FetchConnectionError,
    FetchTimeout,
    FetchTLSError,
    redirect_loop,
)

DANGEROUS = ["javascript", "data", "vbscript", "file", "intent"]
LOCAL = ["localhost", "local", "internal"]


def run(url, fetcher, resolver=None, **settings):
    return resolve_redirects(
        url,
        settings=RedirectSettings(**settings),
        dangerous_schemes=DANGEROUS,
        local_host_suffixes=LOCAL,
        fetcher=fetcher,
        resolver=resolver or FakeResolver(),
    )


def test_follows_shortener_to_destination_with_pinned_ip():
    fetcher = FakeFetcher({"https://bit.ly/abc": (301, "https://www.example.com/landing")})
    resolver = FakeResolver({"bit.ly": ["67.199.248.10"]})
    result = run("https://bit.ly/abc", fetcher, resolver)
    assert result.status == rr.COMPLETED
    assert result.final_url == "https://www.example.com/landing"
    assert [h.status_code for h in result.hops] == [301, 200]
    first = fetcher.requests[0]
    assert first.ip == ipaddress.ip_address("67.199.248.10")  # connects to the validated IP
    assert first.host == "bit.ly" and first.method == "HEAD"
    assert resolver.calls == ["bit.ly", "www.example.com"]  # DNS re-resolved for every hop


@pytest.mark.parametrize(
    "location",
    [
        "http://10.0.0.5/admin",  # private IPv4
        "http://169.254.169.254/latest/meta-data/",  # cloud metadata
        "http://[::1]/",  # IPv6 loopback
        "http://[::ffff:127.0.0.1]/",  # IPv4-mapped loopback
        "http://2130706433/",  # decimal 127.0.0.1
        "http://0x7f.1/",  # hex short form
    ],
)
def test_redirect_to_private_ip_is_blocked_before_any_request(location):
    fetcher = FakeFetcher({"https://short.example/x": (302, location)})
    result = run("https://short.example/x", fetcher)
    assert result.status == rr.BLOCKED_PRIVATE_ADDRESS
    assert len(fetcher.requests) == 1  # the private target was never contacted


@pytest.mark.parametrize(
    "location", ["http://localhost:80/", "http://db.internal/", "http://intranet/"]
)
def test_redirect_to_local_names_is_blocked_without_dns(location):
    fetcher = FakeFetcher({"https://short.example/x": (302, location)})
    resolver = FakeResolver()
    result = run("https://short.example/x", fetcher, resolver)
    assert result.status == rr.BLOCKED_PRIVATE_ADDRESS
    assert resolver.calls == ["short.example"]


def test_domain_resolving_to_loopback_is_blocked():
    fetcher = FakeFetcher({"https://short.example/x": (302, "https://evil.example/")})
    resolver = FakeResolver({"evil.example": ["127.0.0.1"]})
    assert run("https://short.example/x", fetcher, resolver).status == rr.BLOCKED_PRIVATE_ADDRESS


def test_any_private_address_in_dns_answer_blocks_rebinding_tricks():
    resolver = FakeResolver({"rebind.example": ["93.184.215.14", "10.0.0.1"]})
    fetcher = FakeFetcher()
    assert run("https://rebind.example/", fetcher, resolver).status == rr.BLOCKED_PRIVATE_ADDRESS
    assert fetcher.requests == []


def test_redirect_chain_exceeding_limit():
    fetcher = FakeFetcher(redirect_loop("loop.example", 10))
    result = run("https://loop.example/0", fetcher, max_hops=3)
    assert result.status == rr.TOO_MANY_REDIRECTS
    assert len(fetcher.requests) == 4  # original + 3 redirects, then stop


def test_chain_within_limit_completes():
    fetcher = FakeFetcher(redirect_loop("loop.example", 3))
    result = run("https://loop.example/0", fetcher, max_hops=3)
    assert result.status == rr.COMPLETED and result.redirect_count == 3


def test_dns_failure_and_dns_timeout():
    fetcher = FakeFetcher()
    assert (
        run(
            "https://gone.example/", fetcher, FakeResolver({"gone.example": DNSResolutionError()})
        ).status
        == rr.DNS_FAILURE
    )
    assert (
        run(
            "https://slow.example/", fetcher, FakeResolver({"slow.example": DNSTimeoutError()})
        ).status
        == rr.TIMEOUT
    )


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (FetchTimeout(), rr.TIMEOUT),
        (FetchTLSError(), rr.TLS_ERROR),
        (FetchConnectionError(), rr.CONNECTION_ERROR),
    ],
)
def test_network_errors_are_reported_not_raised(error, status):
    assert run("https://x.example/", FakeFetcher({"https://x.example/": error})).status == status


def test_total_time_budget():
    class SlowFetcher(FakeFetcher):
        def __call__(self, request):
            time.sleep(0.05)
            return super().__call__(request)

    fetcher = SlowFetcher(redirect_loop("slow.example", 5))
    result = run("https://slow.example/0", fetcher, total_timeout=0.02)
    assert result.status == rr.TIMEOUT and len(fetcher.requests) == 1


@pytest.mark.parametrize(
    ("location", "status"),
    [
        ("javascript:alert(document.cookie)", rr.BLOCKED_DANGEROUS_SCHEME),
        ("intent://scan/#Intent;scheme=zxing;end", rr.BLOCKED_DANGEROUS_SCHEME),
        ("upi://pay?pa=scammer@upi&am=5000", rr.BLOCKED_SCHEME),
        ("ftp://files.example.com/", rr.BLOCKED_SCHEME),
        ("https://example.com:8080/", rr.BLOCKED_PORT),
        ("http://exa$mple.com/", rr.INVALID_REDIRECT),
    ],
)
def test_unsafe_redirect_targets_are_not_followed(location, status):
    fetcher = FakeFetcher({"https://short.example/x": (302, location)})
    result = run("https://short.example/x", fetcher)
    assert result.status == status and len(fetcher.requests) == 1


def test_relative_redirects_and_head_fallback():
    fetcher = FakeFetcher({"https://a.example/x": (405, None)})
    result = run("https://a.example/x", fetcher)
    assert [r.method for r in fetcher.requests] == ["HEAD", "GET"]
    assert result.status == rr.COMPLETED

    fetcher = FakeFetcher({"https://a.example/start": (302, "../next?id=1")})
    assert run("https://a.example/start", fetcher).final_url == "https://a.example/next?id=1"


def test_real_fetcher_reads_status_and_location_only():
    body_requested = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(302)
            self.send_header("Location", "https://example.com/next")
            self.end_headers()

        def do_GET(self):  # pragma: no cover - must not be used for HEAD-capable servers
            body_requested.append(True)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Calls the low-level fetcher directly (the SSRF guard would block 127.0.0.1).
        response = rr.urllib3_fetch(
            FetchRequest(
                "http",
                "test.local",
                ipaddress.ip_address("127.0.0.1"),
                server.server_port,
                "/x",
                "HEAD",
                2,
                2,
            )
        )
    finally:
        server.shutdown()
    assert response.status == 302 and response.location == "https://example.com/next"
    assert body_requested == []


def test_real_fetcher_connection_refused():
    with pytest.raises(FetchConnectionError):
        rr.urllib3_fetch(
            FetchRequest("http", "x.local", ipaddress.ip_address("127.0.0.1"), 1, "/", "HEAD", 1, 1)
        )
