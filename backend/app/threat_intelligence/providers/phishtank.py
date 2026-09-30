"""PhishTank checkurl (optional). Env: PHISHTANK_API_KEY.

PhishTank has not accepted new registrations for a long time, so this provider is only
useful if a team member already has an application key. Sends only the URL.
    in database + verified phish -> LISTED ("phishing")
    in database, not verified    -> PARTIAL (reported but unconfirmed)
    not in database              -> NOT_LISTED
"""

from __future__ import annotations

from urllib.parse import urlencode

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.api_base import ApiProvider, require_ok

ENDPOINT = "https://checkurl.phishtank.com/checkurl/"


class PhishTankProvider(ApiProvider):
    name = "phishtank"

    def _send(self, normalized_url: str, domain: str) -> HttpResponse:
        return self._http.request(
            "POST",
            ENDPOINT,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "phishtank/qrguard",
            },
            body=urlencode(
                {"url": normalized_url, "format": "json", "app_key": self._api_key}
            ).encode(),
            timeout=self.timeout,
        )

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        results = require_ok(response)["results"]
        if not results["in_database"]:
            return self._result(TIStatus.NOT_LISTED)
        if results.get("valid") and results.get("verified"):
            return self._result(TIStatus.LISTED, threat_type="phishing")
        return self._result(TIStatus.PARTIAL, threat_type="phishing", detail="unverified report")
