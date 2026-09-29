"""POST /api/analyze/message end to end (network faked; nothing is contacted)."""

import logging

import pytest

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeProvider, FakeResolver
from tests.integration.test_errors import assert_error

KYC_SCAM = (
    "Dear customer, your SBI account will be BLOCKED today. Update your KYC immediately: "
    "http://sbi-kyc-update.xyz/login"
)


@pytest.fixture
def api():
    app = make_app()
    service = app.extensions["qrguard.url_analysis"]
    service.resolver, service.fetcher = FakeResolver(), FakeFetcher()
    return app.test_client(), service


def post(client, text):
    response = client.post("/api/analyze/message", json={"text": text})
    return response, response.get_json()


def by_source(body, source):
    return [i for i in body["indicators"] if i["source"] == source]


# --- contract -----------------------------------------------------------------------------------
def test_response_shape(api):
    client, _ = api
    response, body = post(client, KYC_SCAM)
    assert response.status_code == 200
    for key in (
        "request_id",
        "input_type",
        "risk_score",
        "risk_level",
        "confidence",
        "verification",
        "summary",
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
    assert body["input_type"] == "message"
    analysis = body["analysis"]
    for key in ("text_length", "language", "preprocessing", "matched_phrases", "links", "entities"):
        assert key in analysis, key
    for row in body["indicators"]:
        assert row["source"] in {"message", "link", "threat_intelligence", "combination"}
        assert {
            "id",
            "severity",
            "title",
            "message",
            "evidence",
            "weight",
            "score_contribution",
        } <= set(row)


def test_kyc_scam_is_malicious_and_explained_by_source(api):
    client, _ = api
    _, body = post(client, KYC_SCAM)
    assert body["risk_score"] == 65 and body["risk_level"] == "MALICIOUS"
    assert {"kyc_account_suspension", "phishing"} <= {c["id"] for c in body["categories"]}
    sources = {s["source"]: s for s in body["score_breakdown"]["sources"]}
    assert sources["message"]["points"] == 50.0
    assert sources["combination"]["indicator_ids"] == ["MSG_COMBO_THREAT_URGENCY_ACTION"]
    assert "BRAND_IN_DOMAIN_NAME" in sources["link"]["indicator_ids"]
    assert body["score_breakdown"]["rule_used"] == "primary_evidence"
    assert body["verification"]["status"] == "UNVERIFIED"
    link = body["analysis"]["links"][0]
    assert link["url"] == "http://sbi-kyc-update.xyz/login" and link["scored"] is True
    assert link["risk_level"] == "SUSPICIOUS"


def test_matched_phrases_explain_where_evidence_was_found(api):
    client, _ = api
    _, body = post(client, KYC_SCAM)
    phrases = {m["indicator"]: m for m in body["analysis"]["matched_phrases"]}
    assert phrases["MSG_ACCOUNT_THREAT"] == {
        "indicator": "MSG_ACCOUNT_THREAT",
        "phrase": "account will be blocked",
        "sentence": 1,
    }
    assert phrases["MSG_LINK_CALL_TO_ACTION"]["phrase"] == "update … [link]"


# --- genuine messages ---------------------------------------------------------------------------
def test_genuine_otp_message_is_safe(api):
    client, _ = api
    _, body = post(
        client, "482913 is your OTP for login. Never share your OTP with anyone. -HDFC Bank"
    )
    assert body["risk_level"] == "SAFE" and body["risk_score"] == 0
    assert "MSG_OTP_REQUEST" not in {i["id"] for i in body["indicators"]}
    assert body["verification"] == {
        "status": "UNVERIFIED",
        "source": None,
        "message": "There is insufficient evidence to establish trust. A SAFE result does not "
        "guarantee that the message is genuine.",
    }
    assert "does not guarantee" in body["summary"]
    assert body["confidence"] == "MEDIUM"


# --- links: may raise, never lower; no double counting ------------------------------------------
def test_trusted_link_does_not_lower_or_verify_a_scam_message(api):
    client, _ = api
    text = "Your account will be blocked. Share the OTP immediately with SBI customer care: https://en.wikipedia.org/"
    _, body = post(client, text)
    _, without = post(client, text.replace(": https://en.wikipedia.org/", "."))
    assert body["risk_score"] >= without["risk_score"]  # a trusted link never lowers the score
    assert body["risk_level"] == "MALICIOUS"
    assert body["verification"]["status"] == "UNVERIFIED"  # a trusted link verifies nothing
    assert all(i["score_contribution"] == 0 for i in by_source(body, "link"))


def test_malicious_link_raises_a_mild_message(api):
    client, _ = api
    _, mild = post(client, "Your reward points expire today.")
    _, with_link = post(
        client, "Your reward points expire today. Redeem: https://hdfcbnak.com/rewards"
    )
    assert mild["risk_level"] == "SAFE"
    assert with_link["risk_score"] >= 60 and with_link["risk_level"] == "MALICIOUS"
    assert with_link["score_breakdown"]["floor_applied"]["indicator"] == "BRAND_LOOKALIKE"


def test_link_words_are_not_counted_by_the_message_rules(api):
    client, _ = api
    _, body = post(client, "https://verify-kyc-otp-login.example/update")
    message_ids = {i["id"] for i in body["indicators"] if i["source"] != "link"}
    assert message_ids == set()
    assert {i["id"] for i in by_source(body, "link")} >= {"URL_PHISHING_KEYWORD"}


def test_only_the_riskiest_link_is_scored(api):
    client, _ = api
    text = "Links: https://www.example.com/a https://hdfcbnak.com/x http://8.8.8.8/y https://z.example/"
    _, body = post(client, text)
    rows = body["analysis"]["links"]
    assert [r["scored"] for r in rows] == [False, True, False, False]
    assert rows[3]["error"] == "not analysed (limit reached)"
    link_ids = [i["id"] for i in by_source(body, "link")]
    assert "BRAND_LOOKALIKE" in link_ids and "URL_IP_HOST" not in link_ids


def test_shortener_in_message_is_followed_safely(api):
    client, service = api
    service.fetcher = FakeFetcher({"https://bit.ly/abc": (301, "http://paypa1.com/login")})
    _, body = post(client, "Claim your refund: https://bit.ly/abc")
    assert body["analysis"]["links"][0]["redirects"]["final_url"] == "http://paypa1.com/login"
    assert body["risk_level"] == "MALICIOUS"


def test_redirect_checks_are_limited_per_message(api):
    client, service = api
    text = "a https://bit.ly/1 b https://bit.ly/2 c https://bit.ly/3"
    post(client, text)
    assert len({r.target for r in service.fetcher.requests}) == 2  # max_links_redirect_checked


def test_threat_intel_listing_on_a_link_sets_90_and_verifies(api):
    client, service = api
    service.threat_intel = ThreatIntelService([FakeProvider("demo-feed", TIStatus.LISTED)])
    _, body = post(client, "Hello, see this: https://www.example.com/page")
    assert body["risk_score"] == 90 and body["risk_level"] == "MALICIOUS"
    assert body["verification"]["source"] == "threat_intelligence"
    assert by_source(body, "threat_intelligence")[0]["id"] == "TI_LISTED"
    assert body["threat_intel"]["providers"] == [{"provider": "demo-feed", "status": "listed"}]


# --- input validation ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"text": ""},
        {"text": "   "},
        {"text": 5},
        {"text": "a" * 5001},
        {"text": "hi", "extra": 1},
    ],
)
def test_invalid_input(api, payload):
    client, _ = api
    assert_error(client.post("/api/analyze/message", json=payload), 400, "VALIDATION_ERROR")


@pytest.mark.parametrize("text", ["🙂🙂🙂", "12345 67890", "!!!"])
def test_text_without_letters_is_not_analyzable(api, text):
    client, _ = api
    response, _ = post(client, text)
    assert_error(response, 422, "TEXT_NOT_ANALYZABLE")


def test_link_only_message_is_analysed(api):
    client, _ = api
    response, body = post(client, "https://hdfcbnak.com")
    assert response.status_code == 200 and body["risk_level"] == "MALICIOUS"


def test_short_and_non_english_messages_have_low_confidence(api):
    client, _ = api
    assert post(client, "Share OTP")[1]["confidence"] == "LOW"
    _, body = post(client, "आपका खाता बंद कर दिया जाएगा, तुरंत केवाईसी अपडेट करें")
    assert body["confidence"] == "LOW"
    assert body["analysis"]["language"] == {"script": "other", "supported": False}
    assert "language not fully supported" in body["analysis"]["low_confidence_reasons"]


# --- privacy ------------------------------------------------------------------------------------
def test_message_text_is_never_logged(api, caplog):
    client, _ = api
    private_text = "UNIQUE-PRIVATE-MARKER-7731 share the OTP"
    with caplog.at_level(logging.DEBUG):
        post(client, private_text)
    assert "UNIQUE-PRIVATE-MARKER-7731" not in caplog.text


def test_phone_numbers_are_masked_in_the_response(api):
    client, _ = api
    response, body = post(client, "You won! Call 9876543210 now")
    assert body["analysis"]["entities"]["phone_numbers"] == ["******3210"]
    assert "9876543210" not in response.get_data(as_text=True)
