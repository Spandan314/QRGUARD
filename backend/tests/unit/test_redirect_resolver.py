"""Redirect checker tests. DNS and HTTP are faked; only the last test uses a real local
HTTP server, calling the low-level fetcher directly to prove it never reads the body."""

import http.server
import ipaddress
import os
import socket
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


# --- hard time limits against a hostile (local) server ------------------------------------------
def _dripping_server(seconds: float):
    """Answers with a 302 whose headers arrive one byte every 0.2 s for ``seconds``."""
    listener = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def handle(conn):
        try:
            conn.recv(4096)
            conn.sendall(b"HTTP/1.1 302 Found\r\nX-Pad: ")
            end = time.monotonic() + seconds
            while time.monotonic() < end and not stop.is_set():
                conn.sendall(b"a")  # always well inside the per-read timeout
                time.sleep(0.2)
            conn.sendall(b"\r\nLocation: https://next.example/\r\n\r\n")
        except OSError:
            pass  # the client hung up, as it should
        finally:
            conn.close()

    def serve():
        listener.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return listener.getsockname()[1], stop


def _local(port):
    """Pretends a validated public host lives on the local test server."""

    def fetch(request):
        return rr.urllib3_fetch(
            FetchRequest(
                request.scheme,
                request.host,
                ipaddress.ip_address("127.0.0.1"),
                port,
                request.target,
                request.method,
                request.connect_timeout,
                request.read_timeout,
                request.deadline,
            )
        )

    return fetch


def test_slow_header_drip_is_cut_at_the_request_deadline():
    port, stop = _dripping_server(10)
    try:
        start = time.monotonic()
        with pytest.raises(FetchTimeout):
            rr.urllib3_fetch(
                FetchRequest(
                    "http",
                    "drip.example",
                    ipaddress.ip_address("127.0.0.1"),
                    port,
                    "/",
                    "HEAD",
                    1,
                    1,
                    1,
                )
            )
        elapsed = time.monotonic() - start
    finally:
        stop.set()
    assert elapsed < 2  # without the watchdog this took the full 10 s


def test_slow_header_drip_cannot_exceed_the_total_budget():
    port, stop = _dripping_server(10)
    try:
        start = time.monotonic()
        result = run("http://drip.example/", _local(port), request_timeout=3, total_timeout=1)
        elapsed = time.monotonic() - start
    finally:
        stop.set()
    assert result.status == rr.TIMEOUT
    assert elapsed < 2


def test_get_fallback_only_gets_what_is_left_of_the_budget():
    class SlowHead(FakeFetcher):
        def __call__(self, request):
            if request.method == "HEAD":
                time.sleep(0.15)
            return super().__call__(request)

    fetcher = SlowHead({"https://a.example/x": (405, None)})
    run("https://a.example/x", fetcher, request_timeout=3, total_timeout=1)
    head, get = fetcher.requests
    assert head.deadline is not None and 0.9 < head.deadline <= 1
    assert get.deadline is not None and get.deadline < 0.9


def test_fast_server_is_unaffected_by_the_watchdog():
    port, stop = _dripping_server(0)
    try:
        result = run("http://quick.example/", _local(port), max_hops=0)
    finally:
        stop.set()
    assert result.status == rr.TOO_MANY_REDIRECTS  # the 302 was read normally
    assert result.hops[0].status_code == 302


# --- concurrency cap ----------------------------------------------------------------------------
def test_checks_beyond_the_worker_limit_are_skipped_not_queued():
    slots = rr.RedirectSlots(limit=1, wait=0.05)
    entered, release = threading.Event(), threading.Event()

    class Blocking(FakeFetcher):
        def __call__(self, request):
            entered.set()
            release.wait(5)
            return super().__call__(request)

    first = []
    worker = threading.Thread(
        target=lambda: first.append(
            resolve_redirects(
                "https://a.example/",
                settings=RedirectSettings(),
                dangerous_schemes=DANGEROUS,
                local_host_suffixes=LOCAL,
                fetcher=Blocking(),
                resolver=FakeResolver(),
                slots=slots,
            )
        )
    )
    worker.start()
    assert entered.wait(5)
    second_fetcher = FakeFetcher()
    second = resolve_redirects(
        "https://b.example/",
        settings=RedirectSettings(),
        dangerous_schemes=DANGEROUS,
        local_host_suffixes=LOCAL,
        fetcher=second_fetcher,
        resolver=FakeResolver(),
        slots=slots,
    )
    assert second.status == rr.CAPACITY_EXHAUSTED and second_fetcher.requests == []
    release.set()
    worker.join(5)
    assert first[0].status == rr.COMPLETED
    # the slot is free again
    third = resolve_redirects(
        "https://c.example/",
        settings=RedirectSettings(),
        dangerous_schemes=DANGEROUS,
        local_host_suffixes=LOCAL,
        fetcher=FakeFetcher(),
        resolver=FakeResolver(),
        slots=slots,
    )
    assert third.status == rr.COMPLETED


def test_busy_dns_is_reported_as_capacity_exhausted():
    from app.utils.net_safety import DNSBusyError

    result = run("https://a.example/", FakeFetcher(), FakeResolver({"a.example": DNSBusyError()}))
    assert result.status == rr.CAPACITY_EXHAUSTED


def test_stalled_https_handshake_is_cut_at_the_request_deadline():
    # ssl.wrap_socket() detaches the original socket before the handshake: the watchdog must
    # still be able to cut a server that accepts TCP but never answers the TLS ClientHello.
    listener = socket.create_server(("127.0.0.1", 0))
    accepted = []
    threading.Thread(target=lambda: accepted.append(listener.accept()), daemon=True).start()
    try:
        start = time.monotonic()
        with pytest.raises(FetchTimeout):
            rr.urllib3_fetch(
                FetchRequest(
                    "https",
                    "stall.example",
                    ipaddress.ip_address("127.0.0.1"),
                    listener.getsockname()[1],
                    "/",
                    "HEAD",
                    5,
                    5,
                    1,
                )
            )
        elapsed = time.monotonic() - start
    finally:
        listener.close()
        for conn, _ in accepted:
            conn.close()
    assert elapsed < 2  # the 5 s socket timeouts never come into play


def test_the_watchdog_leaves_no_open_sockets_behind():
    def open_descriptors():
        return len(os.listdir("/proc/self/fd"))

    port, stop = _dripping_server(0)
    try:
        run("http://quick.example/", _local(port), max_hops=0)  # warm-up (imports, pools)
        before = open_descriptors()
        for _ in range(5):
            run("http://quick.example/", _local(port), max_hops=0)
        after = open_descriptors()
    finally:
        stop.set()
    assert after <= before
