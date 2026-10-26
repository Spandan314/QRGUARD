"""Providers against complete response bodies in each provider's DOCUMENTED format.

The bodies below follow the structure of the official API documentation (Google Safe Browsing
v4 threatMatches:find, URLhaus v1 /url/, PhishTank checkurl JSON, VirusTotal v3 /urls/{id}),
including the extra fields real answers carry. They were written from that documentation, not
recorded live: this environment cannot reach the providers. A live check of configured keys is
done with ``python -m scripts.ti_selftest`` (docs/deployment.md §2a).
"""

import json

import pytest

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.providers.phishtank import PhishTankProvider
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider, url_id
from tests.fakes import FakeHttp

KEY = "test-key-not-real"
URL = "http://phish.example/login"


# --- Google Safe Browsing ----------------------------------------------------------------------
GSB_MATCH = {
    "matches": [
        {
            "threatType": "SOCIAL_ENGINEERING",
            "platformType": "ANY_PLATFORM",
            "threatEntryType": "URL",
            "threat": {"url": URL},
            "threatEntryMetadata": {
                "entries": [{"key": "malware_threat_type", "value": "landing"}]
            },
            "cacheDuration": "300s",
        }
    ]
}


def test_safe_browsing_documented_match():
    http = FakeHttp(200, GSB_MATCH)
    result = SafeBrowsingProvider(KEY, http=http).check_url(URL, "phish.example")
    assert (result.status, result.threat_type) == (TIStatus.LISTED, "phishing")
    sent = json.loads(http.requests[0]["body"])
    assert sent["threatInfo"]["threatEntries"] == [{"url": URL}]
    assert sent["threatInfo"]["threatTypes"] == [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
    ]


def test_safe_browsing_documented_no_match_is_an_empty_object():
    assert SafeBrowsingProvider(KEY, http=FakeHttp(200, {})).check_url(URL, "x").status == (
        TIStatus.NOT_LISTED
    )


def test_safe_browsing_documented_error_body_is_a_configuration_error():
    body = {"error": {"code": 400, "message": "API key not valid.", "status": "INVALID_ARGUMENT"}}
    result = SafeBrowsingProvider(KEY, http=FakeHttp(400, body)).check_url(URL, "x")
    assert (result.status, result.detail) == (TIStatus.ERROR, "configuration")
    body403 = {"error": {"code": 403, "message": "API not enabled", "status": "PERMISSION_DENIED"}}
    result = SafeBrowsingProvider(KEY, http=FakeHttp(403, body403)).check_url(URL, "x")
    assert (result.status, result.detail) == (TIStatus.ERROR, "configuration")


# --- URLhaus -------------------------------------------------------------------------------------
URLHAUS_OK = {
    "query_status": "ok",
    "id": "105821",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/105821/",
    "url": URL,
    "url_status": "online",
    "host": "phish.example",
    "date_added": "2026-10-01 10:00:00 UTC",
    "last_online": None,
    "threat": "malware_download",
    "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
    "reporter": "abuse_ch",
    "larted": "true",
    "takedown_time_seconds": None,
    "tags": ["elf", "Mozi"],
    "payloads": [],
}


def test_urlhaus_documented_listing():
    http = FakeHttp(200, URLHAUS_OK)
    result = UrlhausProvider(KEY, http=http).check_url(URL, "phish.example")
    assert (result.status, result.threat_type, result.detail) == (
        TIStatus.LISTED,
        "malware_download",
        "url_status: online",
    )
    assert http.requests[0]["headers"]["Auth-Key"] == KEY
    assert http.requests[0]["body"] == b"url=http%3A%2F%2Fphish.example%2Flogin"


@pytest.mark.parametrize("query_status", ["no_results", "invalid_url"])
def test_urlhaus_documented_no_match(query_status):
    result = UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": query_status})).check_url(
        URL, "x"
    )
    assert result.status == TIStatus.NOT_LISTED


@pytest.mark.parametrize(
    ("query_status", "status", "detail"),
    [
        ("unknown_auth_key", TIStatus.ERROR, "configuration"),
        ("http_post_expected", TIStatus.UNAVAILABLE, "unexpected response"),
    ],
)
def test_urlhaus_documented_error_statuses_are_never_clean(query_status, status, detail):
    result = UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": query_status})).check_url(
        URL, "x"
    )
    assert (result.status, result.detail) == (status, detail)


# --- PhishTank -----------------------------------------------------------------------------------
META = {
    "timestamp": "2026-10-26T12:00:00+00:00",
    "serverid": "abc",
    "status": "success",
    "requestid": "1",
}


def test_phishtank_documented_verified_phish():
    body = {
        "meta": META,
        "results": {
            "url": URL,
            "in_database": True,
            "phish_id": "5420916",
            "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=5420916",
            "verified": True,
            "verified_at": "2026-10-20T08:00:00+00:00",
            "valid": True,
        },
    }
    result = PhishTankProvider(KEY, http=FakeHttp(200, body)).check_url(URL, "x")
    assert (result.status, result.threat_type) == (TIStatus.LISTED, "phishing")


def test_phishtank_documented_not_in_database():
    body = {"meta": META, "results": {"url": URL, "in_database": False}}
    assert PhishTankProvider(KEY, http=FakeHttp(200, body)).check_url(URL, "x").status == (
        TIStatus.NOT_LISTED
    )


def test_phishtank_bandwidth_limit_is_rate_limited():
    result = PhishTankProvider(KEY, http=FakeHttp(509, None)).check_url(URL, "x")
    assert (result.status, result.detail) == (TIStatus.UNAVAILABLE, "rate limited")


# --- VirusTotal ----------------------------------------------------------------------------------
def vt_report(**stats):
    return {
        "data": {
            "type": "url",
            "id": url_id(URL),
            "links": {"self": f"https://www.virustotal.com/api/v3/urls/{url_id(URL)}"},
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 60,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 25,
                    "timeout": 0,
                    **stats,
                },
                "last_final_url": URL,
                "reputation": 0,
                "total_votes": {"harmless": 0, "malicious": 0},
            },
        }
    }


@pytest.mark.parametrize(
    ("stats", "status"),
    [
        ({"malicious": 7}, TIStatus.LISTED),
        ({"malicious": 1}, TIStatus.PARTIAL),
        ({}, TIStatus.NOT_LISTED),
    ],
)
def test_virustotal_documented_report(stats, status):
    http = FakeHttp(200, vt_report(**stats))
    result = VirusTotalProvider(KEY, http=http).check_url(URL, "x")
    assert result.status == status
    assert http.requests[0]["method"] == "GET"  # lookup only, never a scan submission
    assert http.requests[0]["url"].endswith(url_id(URL))


def test_virustotal_documented_not_found():
    body = {"error": {"code": "NotFoundError", "message": f'URL "{url_id(URL)}" not found'}}
    result = VirusTotalProvider(KEY, http=FakeHttp(404, body)).check_url(URL, "x")
    assert result.status == TIStatus.NOT_LISTED


def test_phishtank_anonymous_mode_sends_no_key_and_is_off_by_default():
    assert not PhishTankProvider("", http=FakeHttp()).is_enabled()
    http = FakeHttp(200, {"meta": META, "results": {"url": URL, "in_database": False}})
    provider = PhishTankProvider("", http=http, anonymous=True)
    assert provider.is_enabled()
    assert provider.check_url(URL, "x").status == TIStatus.NOT_LISTED
    assert b"app_key" not in http.requests[0]["body"]
