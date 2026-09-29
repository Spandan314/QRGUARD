"""URLhaus (abuse.ch) URL lookup. Sends only the URL. Env: URLHAUS_AUTH_KEY."""

from __future__ import annotations

from urllib.parse import urlencode

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.api_base import ApiProvider, MalformedResponse, require_ok

ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


class UrlhausProvider(ApiProvider):
    name = "urlhaus"

    def _send(self, normalized_url: str, domain: str) -> HttpResponse:
        return self._http.request(
            "POST",
            ENDPOINT,
            headers={
                "Auth-Key": self._api_key,
                "Content-Type": "application/x-www-form-urlencoded",
            },
            body=urlencode({"url": normalized_url}).encode(),
            timeout=self.timeout,
        )

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        data = require_ok(response)
        status = data["query_status"]
        if status == "ok":
            threat = data.get("threat") or "malware_download"
            detail = f"url_status: {data['url_status']}" if data.get("url_status") else None
            return self._result(TIStatus.LISTED, threat_type=str(threat), detail=detail)
        if status in ("no_results", "invalid_url"):
            return self._result(TIStatus.NOT_LISTED)
        raise MalformedResponse(status)
