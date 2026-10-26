"""Evidence-based verdicts: nothing is called safe for lack of evidence (docs/api-spec.md).

Also the regression tests for the reported "offer.com" problems: the checked, displayed and
openable URL is always exactly the domain the user typed, and a redirect to another website is
reported instead of being hidden.
"""

import io

import pytest

from app.analyzers.ocr import OcrError, OcrUnavailableError
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeOcrEngine, FakeProvider, FakeResolver
from tests.images import blank, qr_png
from tests.integration.test_errors import assert_error


def build(**env):
    app = make_app(**env)
    url = app.extensions["qrguard.url_analysis"]
    url.resolver, url.fetcher = FakeResolver(), FakeFetcher()
    return app


@pytest.fixture
def app():
    return build()


@pytest.fixture
def client(app):
    return app.test_client()


def check(client, url):
    return client.post("/api/analyze/url", json={"url": url})


def checks_by_id(body):
    return {c["id"]: c for c in body["checks"]}


# --- verdicts -----------------------------------------------------------------------------------
def test_unknown_domain_is_unverified_not_safe(client):
    body = check(client, "offer.com").get_json()
    assert body["risk_level"] == "SAFE"  # the score band is unchanged ...
    assert body["verdict"]["label"] == "UNVERIFIED"  # ... but it is never presented as safe
    assert body["verdict"]["confirmed"] is False
    assert "Not verified" in body["verdict"]["title"]
    assert body["verification"]["status"] == "UNVERIFIED"
    assert body["confidence"] == "LOW"


def test_only_a_recognised_domain_gets_the_safe_verdict(client):
    body = check(client, "https://www.google.com/").get_json()
    assert body["verdict"]["label"] == "SAFE"
    assert body["verification"]["source"] == "trusted_domain_list"


def test_demo_blocklist_hit_is_never_a_confirmed_verdict(client):
    body = check(client, "http://secure-sbi-kyc-update.example/login").get_json()
    assert body["verdict"]["label"] == "MALICIOUS"
    assert body["verdict"]["confirmed"] is False
    assert body["verdict"]["evidence"] == "demo_blocklist"
    assert body["verdict"]["title"] == "Malicious – on QRGUARD's demo blocklist"


def test_real_threat_intel_listing_is_a_confirmed_malicious_verdict(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("google_safe_browsing", TIStatus.LISTED, "phishing")]
    )
    body = check(client, "https://offer.com/").get_json()
    assert body["verdict"] == {
        "label": "MALICIOUS",
        "confirmed": True,
        "evidence": "threat_intelligence",
        "title": "Malicious – listed by threat intelligence",
        "explanation": "A threat-intelligence source lists this as known malicious.",
    }


def test_heuristic_malicious_is_not_called_confirmed(client):
    body = check(client, "https://amaz0n-offers.example/deal").get_json()
    assert body["risk_level"] == "MALICIOUS"
    assert body["verdict"]["label"] == "MALICIOUS" and body["verdict"]["confirmed"] is False


def test_messages_without_scam_signs_are_unverified(client):
    text = "Hi, are we still meeting for lunch at 1 pm tomorrow? Let me know."
    body = client.post("/api/analyze/message", json={"text": text}).get_json()
    assert body["risk_level"] == "SAFE"
    assert body["verdict"]["label"] == "UNVERIFIED"
    assert body["verdict"]["title"] == "No scam signs found – not verified"


def test_every_analysis_endpoint_returns_a_verdict(client):
    responses = [
        check(client, "offer.com"),
        client.post(
            "/api/analyze/message", json={"text": "Your parcel is waiting at the post office."}
        ),
        client.post("/api/analyze/qr", json={"content": "https://offer.com/"}),
    ]
    for response in responses:
        assert response.status_code == 200
        assert response.get_json()["verdict"]["label"] in (
            "UNVERIFIED",
            "SAFE",
            "SUSPICIOUS",
            "MALICIOUS",
        )


# --- what was checked ---------------------------------------------------------------------------
def test_checks_report_the_demo_blocklist_as_limited(client):
    body = check(client, "offer.com").get_json()
    checks = checks_by_id(body)
    assert checks["url_structure"]["status"] == "completed"
    assert checks["destination"]["status"] == "not_run"  # shorteners_only (default)
    assert checks["threat_intelligence"] == {
        "id": "threat_intelligence",
        "label": "Threat-intelligence databases",
        "status": "limited",
        "detail": "no real provider is enabled; only QRGUARD's demo blocklist was checked",
    }


@pytest.mark.parametrize(
    ("status", "detail", "expected"),
    [
        (TIStatus.UNAVAILABLE, "timeout", "Google Safe Browsing (timeout)"),
        (TIStatus.UNAVAILABLE, "rate limited", "Google Safe Browsing (rate limited)"),
        (TIStatus.ERROR, "configuration", "Google Safe Browsing (configuration)"),
    ],
)
def test_a_failed_provider_is_never_a_clean_result(app, client, status, detail, expected):
    from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider

    class Failing(ThreatIntelProvider):
        name = "google_safe_browsing"

        def check_url(self, normalized_url, domain):
            return ProviderResult(self.name, status, detail=detail)

    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService([Failing()])
    body = check(client, "offer.com").get_json()
    ti = checks_by_id(body)["threat_intelligence"]
    assert ti["status"] == "unavailable" and ti["detail"] == f"could not be checked: {expected}"
    assert body["confidence"] == "LOW"
    assert (
        body["verdict"]["label"] == "UNVERIFIED" and body["verdict"]["evidence"] == "insufficient"
    )


def test_partly_failed_providers_are_reported_as_incomplete(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [
            FakeProvider("urlhaus", TIStatus.NOT_LISTED),
            FakeProvider("virustotal", TIStatus.UNAVAILABLE),
        ]
    )
    body = check(client, "offer.com").get_json()
    ti = checks_by_id(body)["threat_intelligence"]
    assert ti["status"] == "incomplete"
    assert ti["detail"] == "answered: URLhaus; could not be checked: VirusTotal (no answer)"
    assert body["confidence"] == "LOW"


@pytest.mark.parametrize(
    ("url", "providers", "label", "evidence"),
    [
        ("https://www.google.com/", [], "SAFE", "trusted_list"),
        ("offer.com", [], "UNVERIFIED", "insufficient"),
        ("offer.com", [("urlhaus", TIStatus.NOT_LISTED)], "UNVERIFIED", "insufficient"),
        ("http://paypal-secure-login.xyz/verify", [], "SUSPICIOUS", "warning_signs"),
        ("https://amaz0n-offers.example/deal", [], "MALICIOUS", "warning_signs"),
        ("offer.com", [("urlhaus", TIStatus.LISTED)], "MALICIOUS", "threat_intelligence"),
    ],
)
def test_every_verdict_states_what_it_rests_on(app, client, url, providers, label, evidence):
    if providers:
        app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
            [FakeProvider(name, status) for name, status in providers]
        )
    body = check(client, url).get_json()
    assert (body["verdict"]["label"], body["verdict"]["evidence"]) == (label, evidence)
    if label == "SAFE":
        assert body["verification"]["status"] == "VERIFIED"
    if body["risk_score"] == 0 and label != "SAFE":
        assert body["verdict"]["label"] == "UNVERIFIED"  # a zero score is not proof of safety


def test_checks_name_the_real_providers_that_answered(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("google_safe_browsing", TIStatus.NOT_LISTED)]
    )
    body = check(client, "offer.com").get_json()
    ti = checks_by_id(body)["threat_intelligence"]
    assert ti["status"] == "completed" and ti["detail"] == "Google Safe Browsing"
    assert body["verdict"]["label"] == "UNVERIFIED"  # "not listed" is still not proof of safety


def test_checks_report_unreachable_providers(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("virustotal", TIStatus.UNAVAILABLE)]
    )
    body = check(client, "offer.com").get_json()
    assert checks_by_id(body)["threat_intelligence"]["status"] == "unavailable"


# --- the exact domain is preserved (offer.com vs offers.com) ------------------------------------
@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("offer.com", "https://offer.com/"),
        ("offers.com", "https://offers.com/"),
        ("OFFER.COM", "https://offer.com/"),
        ("Offer.Com/Deals?Id=AbC", "https://offer.com/Deals?Id=AbC"),
        ("https://%6f%66fer.com/", "https://offer.com/"),
        ("https://offer.com.", "https://offer.com/"),
    ],
)
def test_the_checked_url_is_exactly_the_typed_domain(client, typed, expected):
    body = check(client, typed).get_json()
    assert body["analysis"]["normalized_url"] == expected
    assert body["analysis"]["domain"] == expected.split("/")[2].lower()


def test_offer_and_offers_are_different_targets(client):
    one = check(client, "offer.com").get_json()["analysis"]
    two = check(client, "offers.com").get_json()["analysis"]
    assert one["domain"] == "offer.com" and two["domain"] == "offers.com"


def test_a_cross_domain_redirect_is_reported_and_the_target_is_kept(client):
    app = build(REDIRECT_RESOLUTION="all")
    app.extensions["qrguard.url_analysis"].fetcher = FakeFetcher(
        {"https://offer.com/": (301, "https://www.offers.com/")}
    )
    body = check(app.test_client(), "offer.com").get_json()
    assert body["analysis"]["normalized_url"] == "https://offer.com/"  # never replaced
    assert body["analysis"]["redirects"]["final_url"] == "https://www.offers.com/"
    assert "REDIRECT_CROSS_DOMAIN" in [i["id"] for i in body["indicators"]]
    destination = checks_by_id(body)["destination"]
    assert destination == {
        "id": "destination",
        "label": "Where the link leads (redirects)",
        "status": "completed",
        "detail": "leads to another website: offers.com",
    }


def test_a_domain_that_does_not_resolve_is_reported_as_incomplete(client):
    from app.utils.net_safety import DNSResolutionError

    app = build(REDIRECT_RESOLUTION="all")
    app.extensions["qrguard.url_analysis"].resolver = FakeResolver(
        {"no-such-site.com": DNSResolutionError("nxdomain")}
    )
    body = check(app.test_client(), "no-such-site.com").get_json()
    assert checks_by_id(body)["destination"]["status"] == "incomplete"
    assert body["verdict"]["label"] != "SAFE"


@pytest.mark.parametrize(
    "deceptive",
    [
        "https://paypal.com@evil.example/login",
        "https://user:pw@paypal.com.evil.example/",
        "https://secure.sbi.co.in.login-verify.example/",
    ],
)
def test_deceptive_urls_are_analysed_by_their_real_domain(client, deceptive):
    body = check(client, deceptive).get_json()
    assert body["analysis"]["domain"] in ("evil.example", "login-verify.example")
    assert body["verdict"]["label"] in ("SUSPICIOUS", "MALICIOUS")


def test_passwords_in_links_are_never_echoed(client):
    body = check(client, "https://user:secret123@paypal.com.evil.example/").get_json()
    assert "secret123" not in str(body)


# --- malformed input never gets a verdict -------------------------------------------------------
@pytest.mark.parametrize("bare", ["offer", "offer.", "  offer  "])
def test_bare_words_are_rejected_not_guessed(client, bare):
    response = check(client, bare)
    assert_error(response, 400, "INCOMPLETE_URL")
    assert "offer" in response.get_json()["error"]["message"]


@pytest.mark.parametrize("bad", ["offer com", "http://", "https://a..com", "javascript:alert(1)"])
def test_other_malformed_or_dangerous_input_is_never_safe(client, bad):
    response = check(client, bad)
    if response.status_code == 200:
        assert response.get_json()["verdict"]["label"] in ("SUSPICIOUS", "MALICIOUS")
    else:
        assert response.status_code == 400


def test_an_unknown_domain_ending_is_explained_and_unverified(client):
    body = check(client, "offer.c").get_json()
    assert "URL_UNKNOWN_TLD" in [i["id"] for i in body["indicators"]]
    assert body["verdict"]["label"] == "UNVERIFIED"


def test_explicit_local_names_are_still_analysed(client):
    body = check(client, "http://intranet/login").get_json()
    assert "URL_PRIVATE_NETWORK_HOST" in [i["id"] for i in body["indicators"]]


# --- one image flow: QR codes still work when OCR cannot ----------------------------------------
def upload(client, data):
    return client.post(
        "/api/analyze/screenshot",
        data={"file": (io.BytesIO(data), "image.png")},
        content_type="multipart/form-data",
    )


@pytest.mark.parametrize("error", [OcrError("timeout"), OcrUnavailableError("no tesseract")])
def test_a_qr_photo_is_analysed_even_when_ocr_fails(app, client, error):
    app.extensions["qrguard.screenshot_analysis"].ocr_engine = FakeOcrEngine(error=error)
    response = upload(client, qr_png("https://offer.com/"))
    assert response.status_code == 200
    body = response.get_json()
    assert body["analysis"]["qr"]["decoded_content"] == "https://offer.com/"
    assert body["analysis"]["ocr"] is None
    assert body["verdict"]["label"] == "UNVERIFIED"


def test_ocr_failure_without_a_qr_code_is_still_an_error(app, client):
    app.extensions["qrguard.screenshot_analysis"].ocr_engine = FakeOcrEngine(error=OcrError("x"))
    assert_error(upload(client, blank()), 422, "OCR_FAILED")
