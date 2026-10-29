"""Domain registration age from RDAP, the registries' standard successor to WHOIS.

Which server answers for a domain ending comes from IANA's RDAP bootstrap file
(https://data.iana.org/rdap/dns.json), so QRGUARD only ever contacts IANA and the official
registry servers listed there, never a host taken from the link being checked. The suspicious
website itself is not contacted. Requests use the threat-intelligence HTTP client: verified
HTTPS, a strict timeout, no redirects, no retries and a 1 MB response cap.

Only the registrable domain (e.g. "example.com", never the full URL) is sent to the registry.
An answer that cannot be obtained is reported as unknown: it never adds points and never
counts as evidence that a domain is safe.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any
from urllib.parse import urlsplit

from app.threat_intelligence.http import HttpClient, TIHttpError

logger = logging.getLogger("qrguard.domain_age")

BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
BOOTSTRAP_TTL_SECONDS = 24 * 3600
RESULT_TTL_SECONDS = 24 * 3600
NEW_DOMAIN_DAYS = 30  # "recently registered" below this age
MAX_CACHED_DOMAINS = 5000

# Outcomes (the "status" of a DomainAge)
FOUND = "found"  # registration date known
NO_DATE = "no_date"  # the registry answered without a registration date
NOT_FOUND = "not_found"  # the registry has no record of the domain
UNSUPPORTED = "unsupported"  # no RDAP server is published for this domain ending
UNAVAILABLE = "unavailable"  # timeout, rate limit, network or registry error
DEFINITIVE = {FOUND, NO_DATE, NOT_FOUND}


@dataclass(frozen=True)
class DomainAge:
    domain: str
    status: str
    registered: date | None = None
    age_days: int | None = None
    detail: str | None = None  # short and safe to show, e.g. "timeout", "rate limited"

    @property
    def recently_registered(self) -> bool:
        return self.age_days is not None and self.age_days < NEW_DOMAIN_DAYS

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status,
            "registered": self.registered.isoformat() if self.registered else None,
            "age_days": self.age_days,
            "detail": self.detail,
        }


def parse_bootstrap(data: Any) -> dict[str, str]:
    """Domain ending -> RDAP base URL (HTTPS only), from IANA's bootstrap JSON."""
    servers: dict[str, str] = {}
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        return servers
    for service in data["services"]:
        if not (isinstance(service, list) and len(service) == 2):
            continue
        endings, urls = service
        https = [u for u in urls if isinstance(u, str) and urlsplit(u).scheme == "https"]
        if not https or not isinstance(endings, list):
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for ending in endings:
            if isinstance(ending, str) and ending:
                servers[ending.lower()] = base
    return servers


def registration_date(data: Any) -> date | None:
    """The "registration" event of an RDAP domain object (RFC 9083 §4.5)."""
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return None
    for event in events:
        if isinstance(event, dict) and event.get("eventAction") == "registration":
            raw = event.get("eventDate")
            if isinstance(raw, str):
                try:
                    return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
                except ValueError:
                    return None
    return None


class DomainAgeService:
    """Looks up registration dates, with caching. Never raises: problems become UNAVAILABLE."""

    def __init__(
        self,
        http: HttpClient,
        *,
        enabled: bool,
        timeout: float = 3.0,
        clock: Callable[[], float] = time.monotonic,
        today: Callable[[], date] = lambda: datetime.now(UTC).date(),
    ) -> None:
        self.enabled = enabled
        self.timeout = timeout
        self._http = http
        self._clock = clock
        self._today = today
        self._lock = threading.Lock()
        self._servers: dict[str, str] | None = None
        self._servers_at = 0.0
        self._cache: dict[str, tuple[float, DomainAge]] = {}
        self._executor = (
            ThreadPoolExecutor(max_workers=4, thread_name_prefix="rdap") if enabled else None
        )

    def submit(self, domain: str) -> Future[DomainAge]:
        """Start a lookup in the background (it runs alongside the other checks)."""
        if self._executor is None:
            future: Future[DomainAge] = Future()
            future.set_result(DomainAge(domain, UNAVAILABLE, detail="disabled"))
            return future
        return self._executor.submit(self.lookup, domain)

    def lookup(self, domain: str) -> DomainAge:
        domain = domain.lower().rstrip(".")
        with self._lock:
            hit = self._cache.get(domain)
        if hit and self._clock() - hit[0] < RESULT_TTL_SECONDS:
            return hit[1]
        try:
            result = self._lookup(domain)
        except Exception:  # a broken registry answer must never break the analysis
            logger.warning("domain age lookup failed", extra={"event": "rdap_error"})
            result = DomainAge(domain, UNAVAILABLE, detail="unexpected response")
        if result.status in DEFINITIVE:
            with self._lock:
                if len(self._cache) >= MAX_CACHED_DOMAINS:
                    self._cache.clear()
                self._cache[domain] = (self._clock(), result)
        return result

    # ----- internals ----------------------------------------------------------------------------
    def _lookup(self, domain: str) -> DomainAge:
        servers = self._bootstrap()
        if servers is None:
            return DomainAge(domain, UNAVAILABLE, detail="registry list unavailable")
        base = servers.get(domain.rsplit(".", 1)[-1])
        if base is None:
            return DomainAge(domain, UNSUPPORTED, detail="no RDAP service for this domain ending")
        try:
            response = self._http.request(
                "GET",
                f"{base}domain/{domain}",
                headers={"Accept": "application/rdap+json"},
                timeout=self.timeout,
            )
        except TIHttpError as exc:
            return DomainAge(domain, UNAVAILABLE, detail=str(exc) or "network error")
        if response.status == 404:
            return DomainAge(domain, NOT_FOUND, detail="the registry has no record of this domain")
        if response.status == 429:
            return DomainAge(domain, UNAVAILABLE, detail="rate limited")
        if response.status != 200:
            return DomainAge(domain, UNAVAILABLE, detail="registry error")
        registered = registration_date(response.data)
        if registered is None:
            return DomainAge(
                domain, NO_DATE, detail="the registry does not publish a registration date"
            )
        age = max(0, (self._today() - registered).days)
        return DomainAge(domain, FOUND, registered=registered, age_days=age)

    def _bootstrap(self) -> dict[str, str] | None:
        with self._lock:
            if (
                self._servers is not None
                and self._clock() - self._servers_at < BOOTSTRAP_TTL_SECONDS
            ):
                return self._servers
        try:
            response = self._http.request("GET", BOOTSTRAP_URL, timeout=self.timeout)
        except TIHttpError:
            return self._servers  # keep a stale list rather than nothing
        servers = parse_bootstrap(response.data) if response.status == 200 else {}
        if not servers:
            return self._servers
        with self._lock:
            self._servers, self._servers_at = servers, self._clock()
        return servers
