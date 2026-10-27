"""SSRF-safe redirect checking.

Finds where a link (usually a URL shortener) really leads, WITHOUT turning the server
into a proxy for attackers. For every hop:

1. Only http/https are followed. Dangerous schemes (javascript:, data:, intent:...) and other
   schemes (upi:, tel:...) stop the check and are reported.
2. Only ports 80 and 443 are allowed.
3. The hostname is resolved; EVERY returned address must be public (no localhost,
   private, link-local/cloud-metadata, multicast, reserved... see net_safety.is_public_ip).
4. The request connects to that already-validated IP ("IP pinning"), sending the real
   hostname in the Host header / TLS SNI. A second DNS answer cannot switch us to an
   internal address between the check and the connection (DNS rebinding).
5. A HEAD request is sent (GET only if HEAD is refused). The response body is NEVER
   read (0 bytes); only the status code and Location header are used. Nothing downloaded
   is stored or executed.
6. Every redirect target is re-validated from step 1 (fresh DNS resolution), up to a
   maximum number of hops.
7. Time is bounded by the wall clock, not only by socket timeouts: a socket read timeout restarts
   on every byte, so a hostile server dripping one header byte at a time could hold a request
   forever. A watchdog shuts the socket down when the request's own deadline (never later than
   the total budget) expires.
8. Each worker process runs only a few checks at once (``RedirectSlots``). When they are all busy
   the check is skipped and reported as incomplete, so slow hostile links cannot occupy every
   request thread.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import certifi
import urllib3
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.exceptions import (
    ConnectTimeoutError,
    HTTPError,
    NewConnectionError,
    ReadTimeoutError,
    SSLError,
)

from app.analyzers.url_normalizer import URLValidationError, to_ascii_host
from app.utils.net_safety import (
    DNSBusyError,
    DNSResolutionError,
    DNSTimeoutError,
    IPAddress,
    is_public_ip,
    parse_ip_literal,
    resolve_host,
)

ALLOWED_SCHEMES = {"http": 80, "https": 443}
ALLOWED_PORTS = {80, 443}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_LOCATION_LENGTH = 2048
USER_AGENT = "QRGUARD-LinkCheck/0.1 (security analysis; no content downloaded)"

# Result statuses
COMPLETED = "completed"
NOT_ATTEMPTED = "not_attempted"
TOO_MANY_REDIRECTS = "too_many_redirects"
BLOCKED_PRIVATE_ADDRESS = "blocked_private_address"
BLOCKED_DANGEROUS_SCHEME = "blocked_dangerous_scheme"
BLOCKED_SCHEME = "blocked_scheme"
BLOCKED_PORT = "blocked_port"
DNS_FAILURE = "dns_failure"
TIMEOUT = "timeout"
CONNECTION_ERROR = "connection_error"
TLS_ERROR = "tls_error"
INVALID_REDIRECT = "invalid_redirect"
CAPACITY_EXHAUSTED = "capacity_exhausted"  # every redirect-check slot of this worker was busy


class FetchTimeout(Exception):
    pass


class FetchTLSError(Exception):
    pass


class FetchConnectionError(Exception):
    pass


@dataclass(frozen=True)
class FetchRequest:
    scheme: str
    host: str  # hostname sent in Host header / SNI
    ip: IPAddress  # validated address we actually connect to
    port: int
    target: str  # path + query
    method: str
    connect_timeout: float
    read_timeout: float
    deadline: float | None = None  # hard wall-clock limit (s); default: the larger timeout


@dataclass(frozen=True)
class FetchResponse:
    status: int
    location: str | None


Fetcher = Callable[[FetchRequest], FetchResponse]
Resolver = Callable[[str, int, float], list[IPAddress]]


@dataclass
class Hop:
    url: str
    status_code: int

    def to_dict(self) -> dict:
        return {"url": self.url, "status_code": self.status_code}


@dataclass
class RedirectResult:
    status: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str | None = None
    blocked_url: str | None = None  # the redirect target we refused to follow

    @property
    def redirect_count(self) -> int:
        return max(0, len(self.hops) - 1) if self.status == COMPLETED else len(self.hops)


@dataclass(frozen=True)
class RedirectSettings:
    max_hops: int = 5
    request_timeout: float = 3.0
    total_timeout: float = 8.0
    max_concurrent: int = 2  # redirect checks running at once in one worker process
    slot_wait: float = 0.5  # how long a check may wait for a free slot before giving up


class RedirectSlots:
    """Caps the redirect checks one worker process runs at the same time."""

    def __init__(self, limit: int, wait: float) -> None:
        self._semaphore = threading.BoundedSemaphore(limit)
        self._wait = wait

    @contextmanager
    def acquire(self) -> Iterator[bool]:
        acquired = self._semaphore.acquire(timeout=self._wait)
        try:
            yield acquired
        finally:
            if acquired:
                self._semaphore.release()


class _Deadline:
    """Shuts the request's socket down when its wall-clock deadline passes.

    shutdown() ends any blocking connect, TLS handshake or read on that socket at once, which
    a per-read timeout cannot do against a server that keeps sending one byte at a time.

    The watchdog keeps its own duplicate of each socket: for HTTPS, ssl.wrap_socket() detaches
    the original socket object before the handshake, so shutting that object down would do
    nothing. shutdown() acts on the kernel socket shared by both descriptors, and holding our
    own descriptor means we can never hit an unrelated socket that reused a closed number.
    """

    def __init__(self, seconds: float) -> None:
        self.expired = False
        self._finished = False
        self._sockets: list[socket.socket] = []
        self._lock = threading.Lock()
        self._timer = threading.Timer(seconds, self._expire)
        self._timer.daemon = True

    def track(self, sock: socket.socket) -> None:
        with self._lock:
            if self._finished:
                return
            duplicate = sock.dup()
            self._sockets.append(duplicate)
            if self.expired:
                _shutdown(duplicate)

    def _expire(self) -> None:
        with self._lock:
            if self._finished:
                return
            self.expired = True
            for sock in self._sockets:
                _shutdown(sock)

    def __enter__(self) -> _Deadline:
        self._timer.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._timer.cancel()
        with self._lock:
            self._finished = True
            for sock in self._sockets:
                sock.close()
            self._sockets.clear()


def _shutdown(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass  # already closed


def _watched(base: type[HTTPConnection], deadline: _Deadline) -> type[HTTPConnection]:
    """A connection class that registers its socket with ``deadline`` as soon as it exists."""

    class Watched(base):  # type: ignore[valid-type,misc]
        def _new_conn(self) -> socket.socket:
            sock = super()._new_conn()
            deadline.track(sock)
            return sock

    return Watched


def urllib3_fetch(request: FetchRequest) -> FetchResponse:
    """Send one HEAD/GET to a pinned IP and return only status + Location (no body)."""
    timeout = urllib3.Timeout(connect=request.connect_timeout, read=request.read_timeout)
    common = {"port": request.port, "timeout": timeout, "retries": False, "maxsize": 1}
    deadline = _Deadline(request.deadline or max(request.connect_timeout, request.read_timeout))
    if request.scheme == "https":
        pool: urllib3.HTTPConnectionPool = urllib3.HTTPSConnectionPool(
            str(request.ip),
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            assert_hostname=request.host,  # certificate must match the real hostname
            server_hostname=request.host,  # TLS SNI
            **common,
        )
        pool.ConnectionCls = _watched(HTTPSConnection, deadline)
    else:
        pool = urllib3.HTTPConnectionPool(str(request.ip), **common)
        pool.ConnectionCls = _watched(HTTPConnection, deadline)

    headers = {
        "Host": request.host,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    try:
        with deadline:
            response = pool.urlopen(
                request.method,
                request.target,
                headers=headers,
                redirect=False,
                retries=False,
                preload_content=False,  # do not download the body
                assert_same_host=False,
            )
            try:
                # A cut connection can look like headers that simply ended: never trust them.
                if deadline.expired:
                    raise FetchTimeout("request exceeded its time limit")
                return FetchResponse(response.status, response.headers.get("Location"))
            finally:
                response.close()  # close without reading the body
    except (HTTPError, OSError) as exc:
        raise _fetch_error(exc, deadline.expired) from exc
    finally:
        pool.close()


def _fetch_error(exc: Exception, deadline_expired: bool) -> Exception:
    if deadline_expired:  # the watchdog cut the connection: whatever broke, it was too slow
        return FetchTimeout("request exceeded its time limit")
    if isinstance(exc, SSLError):
        return FetchTLSError("TLS verification failed")
    if isinstance(exc, NewConnectionError):  # before ConnectTimeoutError (its subclass)
        return FetchConnectionError("connection failed")
    if isinstance(exc, ConnectTimeoutError | ReadTimeoutError | TimeoutError):
        return FetchTimeout("request timed out")
    return FetchConnectionError("connection failed")


def resolve_redirects(
    url: str,
    *,
    settings: RedirectSettings,
    dangerous_schemes: list[str],
    local_host_suffixes: list[str],
    fetcher: Fetcher = urllib3_fetch,
    resolver: Resolver = resolve_host,
    slots: RedirectSlots | None = None,
) -> RedirectResult:
    """Follow redirects from ``url`` safely. Never raises for network problems."""
    if slots is None:
        return _follow(url, settings, dangerous_schemes, local_host_suffixes, fetcher, resolver)
    with slots.acquire() as acquired:
        if not acquired:
            return RedirectResult(CAPACITY_EXHAUSTED)
        return _follow(url, settings, dangerous_schemes, local_host_suffixes, fetcher, resolver)


def _budgeted_request(
    hop: tuple[str, str, IPAddress, int, str], method: str, deadline: float, limit: float
) -> FetchRequest | None:
    """A request limited to what is left of the total budget (None when nothing is left)."""
    left = deadline - time.monotonic()
    if left <= 0:
        return None
    seconds = min(limit, left)
    scheme, host, ip, port, target = hop
    return FetchRequest(scheme, host, ip, port, target, method, seconds, seconds, seconds)


def _follow(
    url: str,
    settings: RedirectSettings,
    dangerous_schemes: list[str],
    local_host_suffixes: list[str],
    fetcher: Fetcher,
    resolver: Resolver,
) -> RedirectResult:
    hops: list[Hop] = []
    current = url
    deadline = time.monotonic() + settings.total_timeout

    for step in range(settings.max_hops + 1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return RedirectResult(TIMEOUT, hops)

        parts = urlsplit(current)
        scheme = parts.scheme.lower()
        blocked = current if step else None
        if scheme in dangerous_schemes:
            return RedirectResult(BLOCKED_DANGEROUS_SCHEME, hops, blocked_url=blocked)
        if scheme not in ALLOWED_SCHEMES:
            return RedirectResult(BLOCKED_SCHEME, hops, blocked_url=blocked)
        try:
            port = parts.port or ALLOWED_SCHEMES[scheme]
            raw_host = parts.hostname or ""
            ip_literal = parse_ip_literal(raw_host) if raw_host else None
            host = str(ip_literal) if ip_literal else to_ascii_host(raw_host)
        except (ValueError, URLValidationError):
            return RedirectResult(INVALID_REDIRECT, hops, blocked_url=blocked)
        if port not in ALLOWED_PORTS:
            return RedirectResult(BLOCKED_PORT, hops, blocked_url=blocked)

        # --- SSRF guard: every address must be public --------------------------------------
        if ip_literal is not None:
            addresses: list[IPAddress] = [ip_literal]
        else:
            if "." not in host or any(
                host == s or host.endswith("." + s) for s in local_host_suffixes
            ):
                return RedirectResult(BLOCKED_PRIVATE_ADDRESS, hops, blocked_url=blocked)
            try:
                addresses = resolver(host, port, min(settings.request_timeout, remaining))
            except DNSBusyError:
                return RedirectResult(CAPACITY_EXHAUSTED, hops, blocked_url=blocked)
            except DNSTimeoutError:
                return RedirectResult(TIMEOUT, hops, blocked_url=blocked)
            except DNSResolutionError:
                return RedirectResult(DNS_FAILURE, hops, blocked_url=blocked)
        if not addresses or not all(is_public_ip(a) for a in addresses):
            return RedirectResult(BLOCKED_PRIVATE_ADDRESS, hops, blocked_url=blocked)

        # --- one request to the pinned, validated address ----------------------------------
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        hop = (scheme, host, addresses[0], port, target)
        try:
            request = _budgeted_request(hop, "HEAD", deadline, settings.request_timeout)
            if request is None:
                return RedirectResult(TIMEOUT, hops)
            response = fetcher(request)
            if response.status in (405, 501):  # server does not support HEAD
                request = _budgeted_request(hop, "GET", deadline, settings.request_timeout)
                if request is None:
                    return RedirectResult(TIMEOUT, hops)
                response = fetcher(request)
        except FetchTimeout:
            return RedirectResult(TIMEOUT, hops)
        except FetchTLSError:
            return RedirectResult(TLS_ERROR, hops)
        except FetchConnectionError:
            return RedirectResult(CONNECTION_ERROR, hops)

        hops.append(Hop(current, response.status))
        if response.status not in REDIRECT_STATUSES or not response.location:
            return RedirectResult(COMPLETED, hops, final_url=current)

        location = response.location.strip()
        if len(location) > MAX_LOCATION_LENGTH or any(ord(c) < 32 for c in location):
            return RedirectResult(INVALID_REDIRECT, hops)
        next_url = urljoin(current, location).split("#", 1)[0]
        if step == settings.max_hops:
            return RedirectResult(TOO_MANY_REDIRECTS, hops, blocked_url=next_url)
        current = next_url

    return RedirectResult(TOO_MANY_REDIRECTS, hops)  # pragma: no cover (loop always returns)
