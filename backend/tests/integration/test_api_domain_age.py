"""Domain registration age inside the URL pipeline: evidence when known, "unknown" (never clean)
when not, and no lookup at all when it is switched off (registry faked, no network)."""

from datetime import date

import pytest

from app.analyzers import domain_age as da
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.http import TIHttpError
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeProvider
from tests.integration.test_api_threat_intel import analyze, offline
from tests.unit.test_domain_age import COM, TODAY, RouteHttp, rdap

NOT_LISTED = [FakeProvider("google_safe_browsing", TIStatus.NOT_LISTED)]


def client_with(routes, *, enabled="true"):
    app = make_app(DOMAIN_AGE_LOOKUP=enabled)
    service = offline(app)
    service.threat_intel = ThreatIntelService(list(NOT_LISTED))
    http = RouteHttp(routes)
    service.domain_age = da.DomainAgeService(http, enabled=enabled == "true", today=lambda: TODAY)
    return app.test_client(), http


def check(body):
    return next((c for c in body["checks"] if c["id"] == "domain_age"), None)


def ids(body):
    return {i["id"] for i in body["indicators"]}


def test_a_newly_registered_domain_is_evidence_with_its_date():
    client, http = client_with(
        {COM + "account-verify-login.com": (200, rdap("2026-10-24T08:00:00Z"))}
    )
    body = analyze(client, "https://account-verify-login.com/secure/signin?id=7")
    assert "DOMAIN_RECENTLY_REGISTERED" in ids(body)
    row = next(i for i in body["indicators"] if i["id"] == "DOMAIN_RECENTLY_REGISTERED")
    assert row["evidence"] == "account-verify-login.com: registered 4 day(s) ago (2026-10-24)"
    assert row["score_contribution"] > 0
    assert (body["risk_score"], body["verdict"]["label"]) == (55, "SUSPICIOUS")  # 35 + 20
    assert check(body) == {
        "id": "domain_age",
        "label": "Domain registration age",
        "status": "completed",
        "detail": "registered 4 day(s) ago (recently registered)",
    }
    assert body["analysis"]["domain_age"]["registered"] == "2026-10-24"
    # Only the registrable domain reached the registry: no path, query or scheme.
    assert http.requests[-1] == COM + "account-verify-login.com"


def test_an_old_domain_adds_nothing_and_says_how_old_it_is():
    client, _ = client_with({COM + "my-small-bakery.com": (200, rdap("2015-03-02T00:00:00Z"))})
    body = analyze(client, "https://my-small-bakery.com/menu")
    assert "DOMAIN_RECENTLY_REGISTERED" not in ids(body)
    assert (body["risk_score"], body["verdict"]["label"]) == (0, "UNVERIFIED")  # old is not "safe"
    assert check(body)["status"] == "completed"
    assert check(body)["detail"] == f"registered {(TODAY - date(2015, 3, 2)).days} day(s) ago"


@pytest.mark.parametrize("failure", [(429, None), (503, None), TIHttpError("timeout")])
def test_an_unreachable_registry_is_unknown_and_lowers_confidence(failure):
    client, _ = client_with({COM + "my-small-bakery.com": failure})
    body = analyze(client, "https://my-small-bakery.com/menu")
    assert check(body)["status"] == "unavailable" and check(body)["detail"].startswith("unknown (")
    assert body["verdict"]["label"] == "UNVERIFIED" and body["confidence"] == "LOW"
    assert body["risk_score"] == 0  # unknown never adds or removes points


def test_no_registry_record_or_no_date_is_limited_not_clean():
    client, _ = client_with(
        {COM + "a-shop.com": (404, None), COM + "b-shop.com": (200, rdap(None))}
    )
    for host in ("a-shop.com", "b-shop.com"):
        body = analyze(client, f"https://{host}/")
        assert check(body)["status"] == "limited"
        assert body["verdict"]["label"] == "UNVERIFIED"


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://www.wikipedia.org/", "recognised domain"),
        ("http://203.0.113.9/login", "not a registered domain name"),
        (
            "https://login-secure.netlify.app/",
            "shared hosting: the domain age says nothing about this site",
        ),
    ],
)
def test_lookups_are_skipped_where_age_means_nothing(url, reason):
    client, http = client_with({})
    body = analyze(client, url)
    assert check(body) == {
        "id": "domain_age",
        "label": "Domain registration age",
        "status": "not_run",
        "detail": reason,
    }
    assert http.requests == []  # nothing was sent anywhere


def test_switched_off_by_default_nothing_is_sent_and_no_check_is_listed():
    client, http = client_with({}, enabled="false")
    body = analyze(client, "https://account-verify-login.com/secure/signin")
    assert check(body) is None and http.requests == []
    assert body["analysis"]["domain_age"] is None
    assert make_app().extensions["qrguard.url_analysis"].domain_age.enabled is False  # the default


def test_a_threat_listing_still_decides_whatever_the_age():
    app = make_app(DOMAIN_AGE_LOOKUP="true")
    service = offline(app)
    service.threat_intel = ThreatIntelService(
        [FakeProvider("google_safe_browsing", TIStatus.LISTED, "phishing")]
    )
    service.domain_age = da.DomainAgeService(
        RouteHttp({COM + "old-site.com": (200, rdap("2001-01-01T00:00:00Z"))}),
        enabled=True,
        today=lambda: TODAY,
    )
    body = analyze(app.test_client(), "https://old-site.com/")
    assert (body["risk_score"], body["verdict"]["label"], body["verification"]["status"]) == (
        90,
        "MALICIOUS",
        "VERIFIED",
    )


def test_a_shortened_link_is_judged_by_the_domain_it_leads_to():
    client, http = client_with({COM + "fresh-offer.com": (200, rdap("2026-10-26T00:00:00Z"))})
    client.application.extensions["qrguard.url_analysis"].fetcher = FakeFetcher(
        {"https://bit.ly/deal": (301, "https://fresh-offer.com/claim")}
    )
    body = analyze(client, "https://bit.ly/deal")
    assert body["analysis"]["redirects"]["final_domain"] == "fresh-offer.com"
    assert "DOMAIN_RECENTLY_REGISTERED" in ids(body)
    assert http.requests[-1] == COM + "fresh-offer.com"  # not the shortener's domain
