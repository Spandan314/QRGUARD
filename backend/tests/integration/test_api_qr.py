"""POST /api/analyze/qr, POST /api/generate/qr and QR codes inside screenshots.

DEMO / TEST DATA only; network is faked (FakeResolver/FakeFetcher), nothing is contacted.
"""

import base64
import io
import logging

import pytest

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeOcrEngine, FakeProvider, FakeResolver
from tests.images import blank, encode, qr_image, qr_png
from tests.integration.test_errors import assert_error


@pytest.fixture
def app():
    app = make_app()
    url = app.extensions["qrguard.url_analysis"]
    url.resolver, url.fetcher = FakeResolver(), FakeFetcher()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def scan(client, content, source="camera"):
    response = client.post("/api/analyze/qr", json={"content": content, "source": source})
    return response, response.get_json()


def upload(client, data, path="/api/analyze/qr"):
    return client.post(
        path, data={"file": (io.BytesIO(data), "qr.png")}, content_type="multipart/form-data"
    )


def ids(body, source=None):
    return [i["id"] for i in body["indicators"] if source is None or i["source"] == source]


# --- decoded content (camera) -------------------------------------------------------------------
def test_url_qr_uses_the_url_analyzer_and_matches_the_url_endpoint(client):
    _, qr = scan(client, "https://hdfcbnak.com/login")
    url = client.post("/api/analyze/url", json={"url": "https://hdfcbnak.com/login"}).get_json()
    assert qr["input_type"] == "qr" and qr["analysis"]["qr"]["content_type"] == "url"
    assert (qr["risk_score"], qr["risk_level"], ids(qr)) == (
        url["risk_score"],
        url["risk_level"],
        ids(url),
    )
    assert qr["analysis"]["normalized_url"] == "https://hdfcbnak.com/login"
    assert "this QR code" in qr["summary"]


def test_trusted_url_qr_is_safe_and_verified(client):
    _, body = scan(client, "https://en.wikipedia.org/wiki/QR_code")
    assert body["risk_level"] == "SAFE"
    assert body["verification"]["source"] == "trusted_domain_list"


def test_dangerous_scheme_qr(client):
    _, body = scan(client, "javascript:alert(document.cookie)")
    assert body["risk_level"] == "MALICIOUS" and body["risk_score"] == 80
    assert body["analysis"]["qr"]["content_type"] == "dangerous"


def test_normal_shop_upi_qr_is_safe(client):
    _, body = scan(client, "upi://pay?pa=shop123@okaxis&pn=Sharma%20Kirana&am=250")
    assert body["risk_level"] == "SAFE"
    assert body["analysis"]["qr"]["parsed"]["payee_name"] == "Sharma Kirana"
    row = next(i for i in body["indicators"] if i["id"] == "QR_UPI_PAYMENT")
    assert "SENDS money" in row["message"] and row["weight"] == 0
    assert "never gives you money" in body["recommendation"]


def test_impersonating_upi_qr_is_suspicious_but_not_malicious_on_its_own(client):
    _, body = scan(
        client, "upi://pay?pa=rahul9876@ybl&pn=SBI%20Refund%20Dept&am=4999&tn=KYC%20refund"
    )
    assert body["risk_level"] == "SUSPICIOUS" and body["risk_score"] == 40
    assert {"QR_UPI_NAME_MISMATCH", "QR_UPI_PRETEXT"} <= set(ids(body))
    assert "upi_scam" in {c["id"] for c in body["categories"]}
    # QR payload evidence is labelled as such, not as a web link
    assert set(ids(body, "qr")) == set(ids(body))
    assert [s["source"] for s in body["score_breakdown"]["sources"]] == ["qr"]


def test_wifi_qr_never_returns_the_password(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response, body = scan(client, "WIFI:T:WPA;S:Home;P:Zq9SECRETpw;;")
    assert body["risk_level"] == "SAFE"
    assert body["analysis"]["qr"]["parsed"]["has_password"] is True
    assert "Zq9SECRETpw" not in response.get_data(as_text=True)
    assert "Zq9SECRETpw" not in caplog.text


def test_open_wifi_is_explained(client):
    _, body = scan(client, "WIFI:T:nopass;S:Free Airport WiFi;;")
    assert ids(body) == ["QR_WIFI_OPEN"] and body["risk_level"] == "SAFE"


@pytest.mark.parametrize(
    ("content", "kind", "expected_id"),
    [
        ("tel:+919876543210", "phone", "QR_PHONE_NUMBER"),
        ("mailto:help@example.com", "email", "QR_EMAIL"),
        ("geo:18.52,73.85", "geo", "QR_GEO_LOCATION"),
        ("market://details?id=com.example.app", "app_link", "QR_APP_LINK"),
    ],
)
def test_informational_payloads(client, content, kind, expected_id):
    _, body = scan(client, content)
    assert body["analysis"]["qr"]["content_type"] == kind
    assert expected_id in ids(body)
    assert body["risk_level"] == "SAFE"


def test_scam_text_in_a_qr_code_uses_the_message_rules(client):
    text = "Congratulations! You won Rs 25 lakh. Pay processing fee Rs 5000 to claim."
    _, qr = scan(client, text)
    message = client.post("/api/analyze/message", json={"text": text}).get_json()
    assert qr["risk_score"] == message["risk_score"] and ids(qr) == ids(message)
    assert qr["analysis"]["qr"]["content_type"] == "text"


def test_sms_body_and_vcard_are_checked_by_the_rules(client):
    _, sms = scan(client, "SMSTO:9876543210:Share the OTP you received with me")
    assert "MSG_OTP_REQUEST" in ids(sms) and "QR_SMS_PREFILLED" in ids(sms)
    _, card = scan(
        client, "BEGIN:VCARD\nVERSION:3.0\nFN:Bank Support\nURL:https://hdfcbnak.com\nEND:VCARD"
    )
    assert "BRAND_LOOKALIKE" in ids(card) and "MSG_EXCESSIVE_CAPS" not in ids(card)


def test_number_only_qr(client):
    response, body = scan(client, "12345")
    assert response.status_code == 200 and body["risk_level"] == "SAFE"


def test_shortener_in_qr_is_followed_ssrf_safely(app, client):
    url = app.extensions["qrguard.url_analysis"]
    url.fetcher = FakeFetcher({"https://bit.ly/menu": (302, "http://10.0.0.8/admin")})
    _, body = scan(client, "https://bit.ly/menu")
    assert body["analysis"]["redirects"]["status"] == "blocked_private_address"
    assert "10.0.0.8" not in str(body["analysis"]["redirects"].get("hops"))


def test_threat_intel_listed_qr_link(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("demo-feed", TIStatus.LISTED)]
    )
    _, body = scan(client, "https://www.example.com/pay")
    assert body["risk_score"] == 90 and body["verification"]["source"] == "threat_intelligence"


@pytest.mark.parametrize(
    "payload", [{}, {"content": ""}, {"content": "x" * 4097}, {"content": "x", "source": "gallery"}]
)
def test_invalid_content_requests(client, payload):
    assert_error(client.post("/api/analyze/qr", json=payload), 400, "VALIDATION_ERROR")


# --- QR images ----------------------------------------------------------------------------------
def test_qr_image_is_decoded_and_analysed(client):
    response = upload(client, qr_png("https://hdfcbnak.com/login"))
    body = response.get_json()
    assert response.status_code == 200 and body["risk_level"] == "MALICIOUS"
    assert body["analysis"]["qr"]["source"] == "image"
    assert body["analysis"]["image"]["format"] == "PNG"


def test_inverted_qr_image(client):
    body = upload(client, qr_png("upi://pay?pa=shop123@okaxis&pn=Shop", invert=True)).get_json()
    assert body["analysis"]["qr"]["content_type"] == "upi"


def test_multiple_qr_codes_riskiest_decides(client):
    body = upload(
        client, qr_png("https://www.example.com/menu", "https://hdfcbnak.com/x", size=260)
    ).get_json()
    rows = body["analysis"]["qr_codes"]
    assert len(rows) == 2 and sum(r["scored"] for r in rows) == 1
    scored = next(r for r in rows if r["scored"])
    assert scored["decoded_content"] == "https://hdfcbnak.com/x"
    assert body["risk_score"] == scored["risk_score"] == max(r["risk_score"] for r in rows)


def test_image_without_qr(client):
    assert_error(upload(client, blank()), 422, "NO_QR_FOUND")


def test_qr_image_upload_validation(client):
    assert_error(upload(client, b"GIF89a fake"), 415, "UNSUPPORTED_MEDIA_TYPE")
    good = qr_png("https://example.com")
    assert_error(upload(client, good[: len(good) // 3]), 422, "UNPROCESSABLE_IMAGE")
    assert_error(upload(client, b""), 400, "EMPTY_FILE")


def test_qr_image_with_jpeg(client):
    body = upload(client, encode(qr_image("https://www.example.com/jpeg", 400), "JPEG")).get_json()
    assert body["analysis"]["qr"]["decoded_content"] == "https://www.example.com/jpeg"


# --- QR codes inside screenshots ----------------------------------------------------------------
def shot_with_qr(app, text, qr_content):
    app.extensions["qrguard.screenshot_analysis"].ocr_engine = FakeOcrEngine(text=text)
    from PIL import Image

    canvas = Image.new("RGB", (900, 500), "white")
    canvas.paste(qr_image(qr_content, 300), (300, 100))
    return encode(canvas)


def test_upi_qr_with_receive_money_text_is_malicious(app, client):
    data = shot_with_qr(
        app,
        "You won Rs 5000 cashback! Scan this QR to receive the money.",
        "upi://pay?pa=win9876@ybl&pn=Cashback&am=5000",
    )
    body = upload(client, data, "/api/analyze/screenshot").get_json()
    assert body["risk_level"] == "MALICIOUS" and body["risk_score"] >= 60
    assert "QR_UPI_RECEIVE_CONTEXT" in ids(body, "qr")
    assert "MSG_PRIZE_REWARD" in ids(body, "message")
    assert body["analysis"]["qr_codes"][0]["used_as"] == "upi_payment"


def test_upi_qr_in_a_normal_bill_screenshot_is_not_escalated(app, client):
    data = shot_with_qr(
        app,
        "Table 4 bill total Rs 640. Thank you for dining with us.",
        "upi://pay?pa=cafe42@okaxis&pn=Cafe%2042&am=640",
    )
    body = upload(client, data, "/api/analyze/screenshot").get_json()
    assert body["risk_level"] == "SAFE" and "QR_UPI_RECEIVE_CONTEXT" not in ids(body)


def test_link_qr_in_screenshot_is_analysed_as_a_link(app, client):
    data = shot_with_qr(app, "Scan to see our offers", "https://hdfcbnak.com/offer")
    body = upload(client, data, "/api/analyze/screenshot").get_json()
    link = body["analysis"]["links"][0]
    assert link["found_in"] == "qr" and link["scored"] is True
    assert body["risk_level"] == "MALICIOUS"


def test_screenshot_with_only_a_qr_code(app, client):
    data = shot_with_qr(app, "", "https://hdfcbnak.com/login")
    response = upload(client, data, "/api/analyze/screenshot")
    body = response.get_json()
    assert response.status_code == 200 and body["input_type"] == "screenshot"
    assert body["analysis"]["qr"]["source"] == "screenshot"
    assert body["analysis"]["ocr"]["extracted_text"] == ""
    assert body["risk_level"] == "MALICIOUS"


# --- generator ----------------------------------------------------------------------------------
def test_generate_png(client):
    response = client.post(
        "/api/generate/qr", json={"type": "url", "data": {"url": "https://example.com/menu"}}
    )
    body = response.get_json()
    assert response.status_code == 200
    assert body["payload"] == "https://example.com/menu" and body["mime"] == "image/png"
    assert base64.b64decode(body["image_base64"]).startswith(b"\x89PNG")


def test_generate_svg(client):
    body = client.post(
        "/api/generate/qr", json={"type": "text", "data": {"text": "hi"}, "format": "svg"}
    ).get_json()
    assert body["mime"] == "image/svg+xml" and "<svg" in body["svg"]


def test_generate_wifi_masks_the_password_in_the_response_and_logs(client, caplog):
    with caplog.at_level(logging.DEBUG):
        response = client.post(
            "/api/generate/qr",
            json={"type": "wifi", "data": {"ssid": "Home", "password": "Zq9SECRETpw"}},
        )
    assert response.get_json()["payload"] == "WIFI:T:WPA;S:Home;P:***;;"
    assert "Zq9SECRETpw" not in response.get_data(as_text=True) and "Zq9SECRETpw" not in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        {"type": "url", "data": {"url": "javascript:alert(1)"}},
        {"type": "wifi", "data": {"ssid": "Home", "password": "short"}},
        {"type": "email", "data": {"to": "nope"}},
        {"type": "text", "data": {"text": "hi", "evil": "x"}},
    ],
)
def test_generate_rejects_invalid_data(client, body):
    assert_error(client.post("/api/generate/qr", json=body), 400, "VALIDATION_ERROR")


def test_generated_code_round_trips_through_the_analyzer(client):
    generated = client.post(
        "/api/generate/qr",
        json={"type": "url", "data": {"url": "https://en.wikipedia.org/wiki/QR_code"}},
    ).get_json()
    body = upload(client, base64.b64decode(generated["image_base64"])).get_json()
    assert body["analysis"]["qr"]["decoded_content"] == "https://en.wikipedia.org/wiki/QR_code"
    assert body["risk_level"] == "SAFE"
