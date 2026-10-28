"""The URL itself is analysed, not only looked up: brandless phishing-shaped links are flagged
from their structure, threat intelligence only adds evidence, and weak signs are never
described as "no known risks" (all providers faked, no network)."""

import pytest

from app.threat_intelligence.base import TIStatus
from tests.fakes import FakeProvider
from tests.integration.test_api_threat_intel import analyze, with_providers

NOT_LISTED = [
    FakeProvider("urlhaus", TIStatus.NOT_LISTED),
    FakeProvider("google_safe_browsing", TIStatus.NOT_LISTED),
]
FAILING = [
    FakeProvider("urlhaus", TIStatus.ERROR),  # rejected key
    FakeProvider("google_safe_browsing", TIStatus.UNAVAILABLE),  # timeout
    FakeProvider("virustotal", TIStatus.DISABLED),  # no key
]


def ids(body):
    return {i["id"] for i in body["indicators"]}


@pytest.mark.parametrize(
    ("url", "score", "indicator"),
    [
        ("https://account-verify-login.com/secure/signin", 35, "URL_KEYWORDS_IN_DOMAIN"),
        ("https://verify-account-now.top/", 40, "URL_KEYWORDS_IN_DOMAIN"),
        ("https://login-secure.netlify.app/", 38, "URL_KEYWORDS_IN_DOMAIN"),
        ("https://www.dropbox.com.download-file.xyz/invoice", 35, "URL_DOMAIN_IN_SUBDOMAIN"),
    ],
)
def test_phishing_shaped_links_are_suspicious_without_any_listing(url, score, indicator):
    body = analyze(with_providers(*NOT_LISTED), url)
    assert (body["risk_score"], body["verdict"]["label"]) == (score, "SUSPICIOUS")
    assert body["verification"]["status"] == "UNVERIFIED"  # nothing confirmed it
    assert indicator in ids(body)
    contributions = {i["id"]: i["score_contribution"] for i in body["indicators"]}
    assert contributions[indicator] > 0  # the reason is shown with its points


@pytest.mark.parametrize(
    "url", ["https://account-verify-login.com/secure/signin", "https://verify-account-now.top/"]
)
def test_failing_providers_never_make_a_phishing_shaped_link_look_clean(url):
    body = analyze(with_providers(*FAILING), url)
    assert body["verdict"]["label"] == "SUSPICIOUS" and body["confidence"] == "LOW"


def test_weak_signs_are_reported_as_such_not_as_no_known_risks():
    body = analyze(
        with_providers(*NOT_LISTED),
        "https://mail.example-hr-portal.com/webmail/login.php?email=a%40b.com",
    )
    assert (body["risk_score"], body["verdict"]["label"]) == (20, "UNVERIFIED")
    assert {"URL_EMAIL_IN_QUERY", "URL_PHISHING_KEYWORD"} <= ids(body)
    assert body["verdict"]["title"] == "Not verified – minor warning signs found"
    assert body["verdict"]["evidence"] == "warning_signs"
    shown = (body["verdict"]["title"] + body["verdict"]["explanation"]).lower()
    assert "no known risks" not in shown and "found no warning signs" not in shown


def test_a_link_without_any_sign_keeps_the_neutral_wording():
    body = analyze(with_providers(*NOT_LISTED), "https://my-small-bakery.in/menu")
    assert (body["risk_score"], body["verdict"]["label"]) == (0, "UNVERIFIED")
    assert body["verdict"]["title"] == "Not verified – no known risks found"
    assert body["verdict"]["evidence"] == "insufficient"


@pytest.mark.parametrize(
    ("url", "score", "level", "absent"),
    [
        # A brand check already describes these domains: the generic signs are not added again.
        ("https://sbi-kyc-verify.top/login", 50, "SUSPICIOUS", "URL_KEYWORDS_IN_DOMAIN"),
        (
            "https://login.microsoftonline.com.secure-auth.ru/oauth",
            60,
            "MALICIOUS",
            "URL_DOMAIN_IN_SUBDOMAIN",
        ),
    ],
)
def test_brand_evidence_is_not_counted_twice(url, score, level, absent):
    body = analyze(with_providers(*NOT_LISTED), url)
    assert (body["risk_score"], body["risk_level"]) == (score, level)
    assert absent not in ids(body)


@pytest.mark.parametrize(
    ("url", "verdict"),
    [
        ("https://secure-shop.com/", "UNVERIFIED"),
        ("https://www.wikipedia.org/", "SAFE"),
        ("https://github.com/login?email=a@b.com", "SAFE"),
    ],
)
def test_ordinary_links_are_not_flagged(url, verdict):
    body = analyze(with_providers(*NOT_LISTED), url)
    assert body["verdict"]["label"] == verdict and body["risk_level"] == "SAFE"


def test_a_listing_still_decides_whatever_the_structure():
    body = analyze(
        with_providers(FakeProvider("google_safe_browsing", TIStatus.LISTED, "phishing")),
        "https://my-small-bakery.in/menu",
    )
    assert (body["risk_score"], body["verdict"]["label"], body["verification"]["status"]) == (
        90,
        "MALICIOUS",
        "VERIFIED",
    )
