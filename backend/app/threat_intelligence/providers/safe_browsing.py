"""Google Safe Browsing Lookup API (v4 threatMatches:find). Env: GOOGLE_SAFE_BROWSING_API_KEY.

Sends only the URL. The API key goes in the query string as Google requires, so request
URLs are never logged (the HTTP client also drops exception text).
"""

from __future__ import annotations

import json

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.api_base import ApiProvider, MalformedResponse, require_ok
from app.version import __version__

ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]
THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted_software",
    "POTENTIALLY_HARMFUL_APPLICATION": "harmful_application",
}


class SafeBrowsingProvider(ApiProvider):
    name = "google_safe_browsing"

    def _send(self, normalized_url: str, domain: str) -> HttpResponse:
        body = {
            "client": {"clientId": "qrguard", "clientVersion": __version__},
            "threatInfo": {
                "threatTypes": THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": normalized_url}],
            },
        }
        return self._http.request(
            "POST",
            f"{ENDPOINT}?key={self._api_key}",
            headers={"Content-Type": "application/json"},
            body=json.dumps(body).encode(),
            timeout=self.timeout,
        )

    def _interpret(self, response: HttpResponse) -> ProviderResult:
        data = require_ok(response)
        if set(data) - {"matches"}:  # "{}" means no match; anything else is unexpected
            raise MalformedResponse("unexpected fields")
        matches = data.get("matches", [])
        if not isinstance(matches, list):
            raise MalformedResponse("matches")
        if not matches:
            return self._result(TIStatus.NOT_LISTED)
        threat = str(matches[0]["threatType"])
        return self._result(TIStatus.LISTED, threat_type=THREAT_LABELS.get(threat, threat.lower()))
