"""POST /api/analyze/url: the 20 required scenarios, end to end through the API.

Network access is replaced with fakes (tests/fakes.py): no test depends on live websites,
DNS, or threat-intelligence APIs.
"""

import pytest

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import (
    BrokenProvider,
    DNSResolutionError,
    FakeFetcher,
    FakeProvider,
    FakeResolver,
    FetchTimeout,
    redirect_loop,
)
from tests.integration.test_errors import assert_error


@pytest.fixture
def api():
    """Client + the URL service, with fake DNS/HTTP installed."""
    app = make_app()
    service = app.extensions["qrguard.url_analysis"]
    service.resolver = FakeResolver()
    service.fetcher = FakeFetcher()
    return app.test_client(), service


def post(client, url):
    response = client.post("/api/analyze/url", json={"url": url})
    return response, response.get_json()


def ids(body):
    return [i["id"] for i in body["indicators"]]


# --- response contract --------------------------------------------------------------------------
def test_response_contains_agreed_fields(api):
    client, _ = api
    response, body = post(client, "https://en.wikipedia.org/wiki/Phishing")
    assert response.status_code == 200
    for key in (
        "request_id",
        "risk_score",
        "risk_level",
        "confidence",
        "categories",
        "indicators",
        "recommendation",
        "score_breakdown",
        "threat_intel",
        "analysis",
        "disclaimer",
        "engine_version",
    ):
        assert key in body, key
    assert body["analysis"]["normalized_url"] == "https://en.wikipedia.org/wiki/Phishing"
    assert body["analysis"]["domain"] == "wikipedia.org"
    assert isinstance(body["analysis"]["features"], dict)
    assert body["request_id"] == response.headers["X-Request-ID"]


def test_indicator_rows_are_explainable(api):
    client, _ = api
    _, body = post(client, "http://8.8.8.8/login")
    row = next(i for i in body["indicators"] if i["id"] == "URL_IP_HOST")
    assert row["severity"] == "high"
    assert row["message"].startswith("The URL uses an IP address")
    assert row["weight"] == 25 and row["score_contribution"] > 0
    assert row["evidence"] == "8.8.8.8"


# --- 1. legitimate HTTPS URL --------------------------------------------------------------------
def test_1_legitimate_trusted_https_url_is_safe(api):
    client, _ = api
    _, body = post(client, "https://en.wikipedia.org/wiki/QR_code")
    assert body["risk_level"] == "SAFE" and body["risk_score"] == 0
    assert body["categories"] == []


def test_1b_clean_but_unknown_https_url_is_unverified_not_safe(api):
    client, _ = api
    _, body = post(client, "https://www.example.com/about")
    assert body["risk_level"] == "UNVERIFIED" and body["risk_score"] == 0
    assert body["confidence"] == "LOW"
    assert "could not be verified" in body["summary"]


# --- 2-9. structural indicators -----------------------------------------------------------------
def test_2_http_url(api):
    client, _ = api
    _, body = post(client, "http://example.com/")
    assert "URL_NO_HTTPS" in ids(body) and body["risk_level"] == "UNVERIFIED"


def test_3_ip_address_url(api):
    client, _ = api
    _, body = post(client, "http://8.8.8.8/secure/login")
    assert {"URL_IP_HOST", "URL_NO_HTTPS"} <= set(ids(body))
    assert body["risk_level"] == "SUSPICIOUS"


def test_4_very_long_url(api):
    client, _ = api
    _, body = post(client, "https://example.com/" + "x" * 300)
    assert "URL_VERY_LONG" in ids(body)
    assert body["analysis"]["features"]["url_length"] > 300


def test_5_url_containing_at_symbol(api):
    client, _ = api
    _, body = post(client, "https://www.sbi.co.in@secure-verify.xyz/login")
    assert {"URL_USERINFO_AT", "OFFICIAL_DOMAIN_IN_USERINFO"} <= set(ids(body))
    assert body["risk_level"] == "MALICIOUS"
    assert body["analysis"]["domain"] == "secure-verify.xyz"


def test_6_excessive_subdomains(api):
    client, _ = api
    _, body = post(client, "https://login.secure.account.update.example.com/")
    assert "URL_MANY_SUBDOMAINS" in ids(body)
    assert body["analysis"]["features"]["subdomain_count"] == 4


def test_7_suspicious_keywords(api):
    client, _ = api
    _, body = post(client, "https://example.com/kyc/update/verify-account")
    assert ids(body).count("URL_PHISHING_KEYWORD") == 3
    assert body["score_breakdown"]["final_score"] == 15  # lexical cap


def test_8_url_shortener_is_followed_safely(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/demo": (301, "https://www.example.com/offer")})
    _, body = post(client, "https://bit.ly/demo")
    assert {"URL_SHORTENER", "REDIRECT_CROSS_DOMAIN"} <= set(ids(body))
    redirects = body["analysis"]["redirects"]
    assert redirects["checked"] and redirects["status"] == "completed"
    assert redirects["final_url"] == "https://www.example.com/offer"
    assert body["risk_level"] == "UNVERIFIED"


def test_8b_shortener_to_lookalike_destination_is_malicious(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/x": (302, "http://paypa1.com/signin")})
    _, body = post(client, "https://bit.ly/x")
    assert "BRAND_LOOKALIKE" in ids(body) and body["risk_level"] == "MALICIOUS"
    row = next(i for i in body["indicators"] if i["id"] == "BRAND_LOOKALIKE")
    assert row["evidence"].startswith("destination:")


def test_non_shortener_links_are_not_contacted_by_default(api):
    client, service = api
    post(client, "https://www.example.com/")
    assert service.fetcher.requests == [] and service.resolver.calls == []


def test_9_punycode_idn(api):
    client, _ = api
    _, body = post(client, "https://xn--pypal-4ve.com/login")
    assert {"URL_PUNYCODE", "URL_MIXED_SCRIPT", "BRAND_LOOKALIKE"} <= set(ids(body))
    assert body["analysis"]["host_unicode"] == "pаypal.com"
    assert body["risk_level"] == "MALICIOUS"


# --- 10. lookalike ------------------------------------------------------------------------------
def test_10_lookalike_bank_domain(api):
    client, _ = api
    _, body = post(client, "https://hdfcbnak.com/netbanking")
    assert body["risk_level"] == "MALICIOUS" and body["risk_score"] >= 60
    assert body["score_breakdown"]["floor_applied"]["indicator"] == "BRAND_LOOKALIKE"
    assert body["analysis"]["brand"] == {"brand": "HDFC Bank", "match_type": "lookalike"}
    assert {"phishing", "impersonation"} <= {c["id"] for c in body["categories"]}


def test_10b_official_bank_domain_is_not_flagged(api):
    client, _ = api
    _, body = post(client, "https://netbanking.hdfcbank.com/netbanking/")
    assert body["risk_level"] == "SAFE"
    assert body["analysis"]["brand"]["match_type"] == "official"


# --- 11-13. invalid input -----------------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://", "https://exa mple.com", "http://exa$mple.com"])
def test_11_invalid_url(api, url):
    client, _ = api
    response, _ = post(client, url)
    assert_error(response, 400, "INVALID_URL")


@pytest.mark.parametrize("url", ["", "   "])
def test_12_empty_url(api, url):
    client, _ = api
    response, body = post(client, url)
    assert_error(response, 400, "VALIDATION_ERROR")
    assert body["error"]["details"][0]["field"] == "url"


def test_13_unsupported_protocol(api):
    client, _ = api
    response, _ = post(client, "ftp://files.example.com/a.zip")
    assert_error(response, 400, "UNSUPPORTED_PROTOCOL")


def test_13b_dangerous_protocol_is_analysed_as_malicious(api):
    client, service = api
    _, body = post(client, "javascript:alert(document.cookie)")
    assert body["risk_level"] == "MALICIOUS" and body["risk_score"] == 80
    assert ids(body) == ["URL_DANGEROUS_SCHEME"]
    assert service.fetcher.requests == []


# --- 14-18. redirect safety ---------------------------------------------------------------------
def test_14_redirect_to_private_ip_is_blocked(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/p": (302, "http://192.168.0.1/admin")})
    _, body = post(client, "https://bit.ly/p")
    assert "REDIRECT_TO_PRIVATE_ADDRESS" in ids(body)
    assert body["analysis"]["redirects"]["status"] == "blocked_private_address"
    assert len(service.fetcher.requests) == 1
    assert body["risk_level"] == "SUSPICIOUS"


def test_15_redirect_to_localhost_is_blocked(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/l": (302, "http://localhost/")})
    _, body = post(client, "https://bit.ly/l")
    assert "REDIRECT_TO_PRIVATE_ADDRESS" in ids(body)
    assert "localhost" not in service.resolver.calls  # never even resolved


def test_15b_shortener_whose_dns_points_to_loopback(api):
    client, service = api
    service.resolver = FakeResolver({"bit.ly": ["127.0.0.1"]})
    _, body = post(client, "https://bit.ly/rebind")
    assert "URL_PRIVATE_NETWORK_HOST" in ids(body) and service.fetcher.requests == []


def test_16_redirect_chain_exceeding_limit(api):
    client, service = api
    loop = redirect_loop("bit.ly", 12)
    service.fetcher = FakeFetcher(loop)
    _, body = post(client, "https://bit.ly/0")
    assert "REDIRECT_CHAIN_TOO_LONG" in ids(body)
    assert body["analysis"]["redirects"]["status"] == "too_many_redirects"
    assert len(service.fetcher.requests) == 6  # default max 5 redirects


def test_17_dns_resolution_failure(api):
    client, service = api
    service.resolver = FakeResolver({"bit.ly": DNSResolutionError()})
    _, body = post(client, "https://bit.ly/gone")
    assert "DOMAIN_NOT_RESOLVING" in ids(body)
    assert body["analysis"]["redirects"]["status"] == "dns_failure"
    assert body["confidence"] == "LOW"


def test_18_timeout(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/slow": FetchTimeout()})
    _, body = post(client, "https://bit.ly/slow")
    assert "REDIRECT_CHECK_INCOMPLETE" in ids(body)
    assert body["analysis"]["redirects"]["status"] == "timeout"
    assert body["confidence"] == "LOW"


def test_blocked_responses_never_reveal_resolved_ip_addresses(api):
    client, service = api
    service.resolver = FakeResolver({"bit.ly": ["10.1.2.3"]})
    response, _ = post(client, "https://bit.ly/internal")
    assert "10.1.2.3" not in response.get_data(as_text=True)


# --- 19-20. threat intelligence (mocked providers) ----------------------------------------------
def test_19_malicious_threat_intel_result(api):
    client, service = api
    service.threat_intel = ThreatIntelService(
        [FakeProvider("demo-feed", TIStatus.LISTED, "phishing")]
    )
    _, body = post(client, "https://www.example.com/login")
    assert body["risk_score"] == 90 and body["risk_level"] == "MALICIOUS"
    assert body["confidence"] == "HIGH"
    assert body["threat_intel"]["providers"] == [
        {"provider": "demo-feed", "status": "listed", "threat_type": "phishing"}
    ]
    assert body["score_breakdown"]["floor_applied"]["indicator"] == "TI_LISTED"


def test_20_clean_url_not_in_threat_databases_is_not_called_safe(api):
    client, service = api
    provider = FakeProvider("demo-feed", TIStatus.NOT_LISTED)
    service.threat_intel = ThreatIntelService([provider])
    _, body = post(client, "https://www.example.com/")
    assert body["risk_level"] == "UNVERIFIED" and body["risk_score"] == 0
    assert body["threat_intel"]["checked"] is True
    assert body["threat_intel"]["providers"] == [{"provider": "demo-feed", "status": "not_listed"}]
    assert "does not mean a link is safe" in body["threat_intel"]["note"]
    modules = {m["module"]: m for m in body["score_breakdown"]["modules"]}
    assert modules["threat_intel"]["applicable"] is False
    assert provider.checked == ["https://www.example.com/"]


def test_broken_provider_does_not_break_analysis(api):
    client, service = api
    service.threat_intel = ThreatIntelService([BrokenProvider()])
    response, body = post(client, "https://www.example.com/")
    assert response.status_code == 200
    assert body["threat_intel"]["providers"] == [{"provider": "broken", "status": "unavailable"}]


def test_threat_intel_not_configured_is_stated_honestly(api):
    client, _ = api
    _, body = post(client, "https://www.example.com/")
    assert body["threat_intel"]["checked"] is False
    assert "not enabled" in body["threat_intel"]["note"]


# --- configuration --------------------------------------------------------------------------------
def test_redirect_resolution_can_be_disabled():
    app = make_app(REDIRECT_RESOLUTION="off")
    service = app.extensions["qrguard.url_analysis"]
    service.fetcher = FakeFetcher()
    body = app.test_client().post("/api/analyze/url", json={"url": "https://bit.ly/x"}).get_json()
    assert body["analysis"]["redirects"] == {
        "checked": False,
        "status": "not_attempted",
        "reason": "disabled",
    }
    assert service.fetcher.requests == []
