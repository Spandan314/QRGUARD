"""Shared behaviour of the key-based API providers (URLhaus, Safe Browsing, VirusTotal...).

- Enabled only when the API key is set (no key -> DISABLED, never an error or a crash).
- Only fixed provider hosts are contacted, over verified HTTPS, with a per-request timeout.
- HTTP 401/403 -> ERROR ("configuration"); 429, 5xx, timeouts, network errors -> UNAVAILABLE.
- A malformed response -> UNAVAILABLE ("unexpected response"); it never counts as "not listed".
- API keys and URLs are never logged and never appear in results.
"""

from __future__ import annotations

import logging

from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus
from app.threat_intelligence.http import HttpClient, HttpResponse, TIHttpError, Urllib3Client

logger = logging.getLogger("qrguard.threat_intel")


class MalformedResponse(ValueError):
    """The provider answered, but not in the documented format."""


class ApiProvider(ThreatIntelProvider):
    external = True

    def __init__(
        self, api_key: str | None, http: HttpClient | None = None, timeout: float = 3.0
    ) -> None:
        self._api_key = (api_key or "").strip()
        self._http = http or Urllib3Client()
        self.timeout = timeout

    def __repr__(self) -> str:  # never show the key, e.g. in debug output
        return f"<{type(self).__name__} enabled={self.is_enabled()}>"

    def is_enabled(self) -> bool:
        return bool(self._api_key)

    def _result(self, status: TIStatus, **kwargs) -> ProviderResult:
        return ProviderResult(self.name, status, **kwargs)

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        if not self.is_enabled():
            return self._result(TIStatus.DISABLED)
        try:
            response = self._send(normalized_url, domain)
        except TIHttpError:
            return self._result(TIStatus.UNAVAILABLE, detail="network error")
        if response.status in (401, 403):
            logger.warning(
                "threat-intel provider rejected the API key",
                extra={"event": "ti_auth_error", "provider": self.name},
            )
            return self._result(TIStatus.ERROR, detail="configuration")
        if response.status == 429:
            return self._result(TIStatus.UNAVAILABLE, detail="rate limited")
        if response.status >= 500:
            return self._result(TIStatus.UNAVAILABLE, detail="provider error")
        try:
            return self._interpret(response)
        except (MalformedResponse, KeyError, TypeError, ValueError, AttributeError):
            logger.warning(
                "threat-intel provider sent an unexpected response",
                extra={"event": "ti_bad_response", "provider": self.name},
            )
            return self._result(TIStatus.UNAVAILABLE, detail="unexpected response")

    # ----- implemented by each provider -------------------------------------------------------
    def _send(self, normalized_url: str, domain: str) -> HttpResponse:
        raise NotImplementedError

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        raise NotImplementedError


def require_ok(response: HttpResponse) -> dict:
    if response.status != 200 or not isinstance(response.data, dict):
        raise MalformedResponse
    return response.data
