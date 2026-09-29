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
   maximum number of hops, within strict per-request and total time limits.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import certifi
import urllib3
from urllib3.exceptions import (
    ConnectTimeoutError,
    HTTPError,
    NewConnectionError,
    ReadTimeoutError,
    SSLError,
)

from app.analyzers.url_normalizer import URLValidationError, to_ascii_host
from app.utils.net_safety import (
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


def urllib3_fetch(request: FetchRequest) -> FetchResponse:
    """Send one HEAD/GET to a pinned IP and return only status + Location (no body)."""
    timeout = urllib3.Timeout(connect=request.connect_timeout, read=request.read_timeout)
    common = {"port": request.port, "timeout": timeout, "retries": False, "maxsize": 1}
    if request.scheme == "https":
        pool: urllib3.HTTPConnectionPool = urllib3.HTTPSConnectionPool(
            str(request.ip),
            cert_reqs="CERT_REQUIRED",
            ca_certs=certifi.where(),
            assert_hostname=request.host,  # certificate must match the real hostname
            server_hostname=request.host,  # TLS SNI
            **common,
        )
    else:
        pool = urllib3.HTTPConnectionPool(str(request.ip), **common)

    headers = {
        "Host": request.host,
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Connection": "close",
    }
    try:
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
            return FetchResponse(response.status, response.headers.get("Location"))
        finally:
            response.close()  # close without reading the body
    except SSLError as exc:
        raise FetchTLSError("TLS verification failed") from exc
    except NewConnectionError as exc:  # must come before ConnectTimeoutError (subclass)
        raise FetchConnectionError("connection failed") from exc
    except (ConnectTimeoutError, ReadTimeoutError, TimeoutError) as exc:
        raise FetchTimeout("request timed out") from exc
    except (HTTPError, OSError) as exc:
        raise FetchConnectionError("connection failed") from exc
    finally:
        pool.close()


def resolve_redirects(
    url: str,
    *,
    settings: RedirectSettings,
    dangerous_schemes: list[str],
    local_host_suffixes: list[str],
    fetcher: Fetcher = urllib3_fetch,
    resolver: Resolver = resolve_host,
) -> RedirectResult:
    """Follow redirects from ``url`` safely. Never raises for network problems."""
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
            except DNSTimeoutError:
                return RedirectResult(TIMEOUT, hops, blocked_url=blocked)
            except DNSResolutionError:
                return RedirectResult(DNS_FAILURE, hops, blocked_url=blocked)
        if not addresses or not all(is_public_ip(a) for a in addresses):
            return RedirectResult(BLOCKED_PRIVATE_ADDRESS, hops, blocked_url=blocked)

        # --- one request to the pinned, validated address ----------------------------------
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        per_request = min(settings.request_timeout, max(remaining, 0.1))
        request = FetchRequest(
            scheme, host, addresses[0], port, target, "HEAD", per_request, per_request
        )
        try:
            response = fetcher(request)
            if response.status in (405, 501):  # server does not support HEAD
                response = fetcher(
                    FetchRequest(
                        scheme, host, addresses[0], port, target, "GET", per_request, per_request
                    )
                )
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
