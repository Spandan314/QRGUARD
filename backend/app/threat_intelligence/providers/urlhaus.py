"""URLhaus (abuse.ch) URL lookup. Sends only the URL. Env: URLHAUS_AUTH_KEY."""

from __future__ import annotations

from urllib.parse import urlencode

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.api_base import ApiProvider, MalformedResponse, require_ok

ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
# URLhaus answers an authentication problem with one of these query_status values.
AUTH_ERRORS = {
    "unknown_auth_key": "auth key rejected",  # the key arrived, URLhaus does not recognise it
    "missing_auth_key": "auth key not sent",  # no key arrived: a QRGUARD bug, not a bad key
}


def _auth_status(response: HttpResponse) -> str | None:
    data = response.data
    status = data.get("query_status") if isinstance(data, dict) else None
    return status if isinstance(status, str) and status in AUTH_ERRORS else None


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

    def _auth_error_detail(self, response: HttpResponse) -> str:
        status = _auth_status(response)
        return AUTH_ERRORS[status] if status else super()._auth_error_detail(response)

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        auth_status = _auth_status(response)
        if auth_status:
            return self._auth_error(response, AUTH_ERRORS[auth_status])
        data = require_ok(response)
        status = data["query_status"]
        if status == "ok":
            threat = data.get("threat") or "malware_download"
            detail = f"url_status: {data['url_status']}" if data.get("url_status") else None
            return self._result(TIStatus.LISTED, threat_type=str(threat), detail=detail)
        if status in ("no_results", "invalid_url"):
            return self._result(TIStatus.NOT_LISTED)
        raise MalformedResponse(status)
