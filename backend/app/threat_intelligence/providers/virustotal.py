"""VirusTotal v3 URL report - LOOKUP ONLY. Env: VIRUSTOTAL_API_KEY.

URLs are never submitted for scanning (submissions become visible to the VirusTotal
community). A URL VirusTotal has never seen (HTTP 404) is "not_listed". Verdicts:
    >= 3 engines say malicious  -> LISTED
    1-2 engines (or >= 3 "suspicious") -> PARTIAL (TI_PARTIAL, weaker evidence)
    otherwise                   -> NOT_LISTED
The public API allows about 4 lookups per minute; above that the provider answers
UNAVAILABLE ("quota") instead of being blocked by VirusTotal.
"""

from __future__ import annotations

import base64
import threading
import time
from collections import deque
from collections.abc import Callable

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.http import HttpClient, HttpResponse
from app.threat_intelligence.providers.api_base import ApiProvider, require_ok

ENDPOINT = "https://www.virustotal.com/api/v3/urls/"
LISTED_MIN_ENGINES = 3


def url_id(url: str) -> str:
    """VirusTotal's URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


class VirusTotalProvider(ApiProvider):
    name = "virustotal"

    def __init__(
        self,
        api_key: str | None,
        http: HttpClient | None = None,
        timeout: float = 3.0,
        max_per_minute: int = 4,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(api_key, http, timeout)
        self.max_per_minute = max_per_minute
        self._clock = clock
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def _take_quota(self) -> bool:
        with self._lock:
            now = self._clock()
            while self._calls and now - self._calls[0] >= 60:
                self._calls.popleft()
            if len(self._calls) >= self.max_per_minute:
                return False
            self._calls.append(now)
            return True

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        if self.is_enabled() and not self._take_quota():
            return self._result(TIStatus.UNAVAILABLE, detail="quota")
        return super().check_url(normalized_url, domain)

    def _send(self, normalized_url: str, domain: str) -> HttpResponse:
        return self._http.request(
            "GET",
            ENDPOINT + url_id(normalized_url),
            headers={"x-apikey": self._api_key},
            timeout=self.timeout,
        )

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        if response.status == 404:
            return self._result(TIStatus.NOT_LISTED, detail="not known to VirusTotal")
        data = require_ok(response)
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious, suspicious = int(stats["malicious"]), int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values())
        detail = f"{malicious}/{total} engines"
        if malicious >= LISTED_MIN_ENGINES:
            return self._result(TIStatus.LISTED, threat_type="malicious", detail=detail)
        if malicious or suspicious >= LISTED_MIN_ENGINES:
            return self._result(TIStatus.PARTIAL, threat_type="suspicious", detail=detail)
        return self._result(TIStatus.NOT_LISTED, detail=detail)
