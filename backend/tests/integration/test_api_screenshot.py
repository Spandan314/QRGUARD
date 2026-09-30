"""POST /api/analyze/screenshot (DEMO / TEST DATA; network faked, nothing is contacted).

Most tests use FakeOcrEngine for deterministic text. Tests marked `real_ocr` run the real
Tesseract engine on generated images and are skipped if Tesseract is not installed.
"""

import io
import logging
import os
import shutil
import tempfile

import pytest
from PIL import Image

from app.analyzers.ocr import OcrBusyError, OcrError, OcrUnavailableError
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeOcrEngine, FakeProvider, FakeResolver
from tests.images import blank, encode, png_with_declared_size, render_text
from tests.integration.test_errors import assert_error

real_ocr = pytest.mark.skipif(shutil.which("tesseract") is None, reason="Tesseract not installed")

KYC_TEXT = (
    "Dear customer, your SBI account will be BLOCKED today. Update your KYC immediately: "
    "http://sbi-kyc-update.xyz/login"
)
GENUINE_TEXT = "482913 is your OTP for login. Never share your OTP with anyone. -HDFC Bank"


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


def use_ocr(app, **kwargs):
    engine = FakeOcrEngine(**kwargs)
    app.extensions["qrguard.screenshot_analysis"].ocr_engine = engine
    return engine


def upload(client, data: bytes, name: str = "screenshot.png", **form):
    return client.post(
        "/api/analyze/screenshot",
        data={"file": (io.BytesIO(data), name), **form},
        content_type="multipart/form-data",
    )


def ids(body, source=None):
    return [i["id"] for i in body["indicators"] if source is None or i["source"] == source]


# --- 1-5: valid screenshots ---------------------------------------------------------------------
def test_1_valid_screenshot_response_shape(app, client):
    use_ocr(app, text=GENUINE_TEXT)
    response = upload(client, blank(800, 600, fmt="JPEG"))
    assert response.status_code == 200
    body = response.get_json()
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
    assert body["input_type"] == "screenshot"
    assert body["analysis"]["ocr"] == {
        "engine": "fake-ocr",
        "extracted_text": GENUINE_TEXT,
        "confidence": 95.0,
        "quality": "good",
        "word_count": len(GENUINE_TEXT.split()),
        "truncated": False,
    }
    assert body["analysis"]["image"] == {
        "format": "JPEG",
        "width": 800,
        "height": 600,
        "size_bytes": len(blank(800, 600, fmt="JPEG")),
    }
    for key in ("matched_phrases", "links", "entities", "language"):
        assert key in body["analysis"]


def test_2_legitimate_text_is_safe_and_unverified(app, client):
    use_ocr(app, text=GENUINE_TEXT)
    body = upload(client, blank()).get_json()
    assert body["risk_level"] == "SAFE" and body["risk_score"] == 0
    assert body["verification"]["status"] == "UNVERIFIED"
    assert "screenshot" in body["verification"]["message"]
    assert "does not guarantee" in body["summary"]


def test_3_scam_message_scores_exactly_like_the_message_endpoint(app, client):
    text = "You received Rs 5000 cashback. Enter your UPI PIN to receive the amount."
    use_ocr(app, text=text)
    shot = upload(client, blank()).get_json()
    message = client.post("/api/analyze/message", json={"text": text}).get_json()
    assert shot["risk_score"] == message["risk_score"] == 65
    assert shot["risk_level"] == message["risk_level"] == "MALICIOUS"
    assert ids(shot) == ids(message)
    assert shot["categories"] == message["categories"]


def test_4_suspicious_url_in_screenshot(app, client):
    use_ocr(app, text="Redeem your points: https://hdfcbnak.com/rewards")
    body = upload(client, blank()).get_json()
    assert "BRAND_LOOKALIKE" in ids(body, "link")
    assert body["risk_level"] == "MALICIOUS"
    assert body["score_breakdown"]["floor_applied"]["indicator"] == "BRAND_LOOKALIKE"


def test_5_scam_message_and_suspicious_url(app, client):
    use_ocr(app, text=KYC_TEXT)
    body = upload(client, blank()).get_json()
    assert body["risk_score"] == 65 and body["risk_level"] == "MALICIOUS"
    sources = {s["source"] for s in body["score_breakdown"]["sources"]}
    assert {"message", "link", "combination"} <= sources
    assert body["analysis"]["links"][0]["url"] == "http://sbi-kyc-update.xyz/login"


# --- 6-10: rejected input -----------------------------------------------------------------------
@pytest.mark.parametrize("text", ["", "   \n  ", "🙂 🙂", "12 34 56"])
def test_6_no_detectable_text(app, client, text):
    use_ocr(app, text=text)
    assert_error(upload(client, blank()), 422, "NO_TEXT_FOUND")


@pytest.mark.parametrize(
    ("data", "name"),
    [
        (encode(Image.new("RGB", (60, 60)), "GIF"), "a.gif"),
        (b"%PDF-1.7 fake", "doc.pdf"),
        (b"MZ\x90\x00 fake exe", "screenshot.png"),  # extension lies; content decides
        (b"<svg><script>alert(1)</script></svg>", "x.svg"),
    ],
)
def test_7_unsupported_file_types(app, client, data, name):
    engine = use_ocr(app, text="anything")
    assert_error(upload(client, data, name), 415, "UNSUPPORTED_MEDIA_TYPE")
    assert engine.calls == 0  # OCR never runs on rejected files


def test_8_malformed_images(app, client):
    engine = use_ocr(app, text="anything")
    good = blank(600, 400, fmt="PNG", color="red")
    assert_error(upload(client, good[: len(good) // 2]), 422, "UNPROCESSABLE_IMAGE")
    assert_error(upload(client, b"\x89PNG\r\n\x1a\n" + b"\x00" * 50), 422, "UNPROCESSABLE_IMAGE")
    assert_error(upload(client, blank(8, 8)), 422, "IMAGE_TOO_SMALL")
    assert engine.calls == 0


def test_9_oversized_images():
    app = build(MAX_UPLOAD_MB="1")
    client = app.test_client()
    use_ocr(app, text="anything")
    noisy = encode(Image.effect_noise((1100, 1100), 80).convert("RGB"), "PNG")  # > 1 MB
    assert len(noisy) > 1024 * 1024
    assert_error(upload(client, noisy), 413, "PAYLOAD_TOO_LARGE")
    assert_error(upload(client, blank(6000, 5000)), 413, "IMAGE_TOO_LARGE")
    assert_error(upload(client, png_with_declared_size(60000, 60000)), 413, "IMAGE_TOO_LARGE")


def test_10_invalid_multipart_requests(app, client):
    use_ocr(app, text=GENUINE_TEXT)
    assert_error(
        client.post("/api/analyze/screenshot", json={"file": "x"}), 415, "UNSUPPORTED_MEDIA_TYPE"
    )
    assert_error(
        client.post(
            "/api/analyze/screenshot",
            data={"image": (io.BytesIO(blank()), "a.png")},
            content_type="multipart/form-data",
        ),
        400,
        "MISSING_FILE",
    )
    two = {"file": [(io.BytesIO(blank()), "a.png"), (io.BytesIO(blank()), "b.png")]}
    assert_error(
        client.post("/api/analyze/screenshot", data=two, content_type="multipart/form-data"),
        400,
        "VALIDATION_ERROR",
    )
    assert_error(upload(client, blank(), save_to_history="maybe"), 400, "VALIDATION_ERROR")
    assert upload(client, blank(), save_to_history="true").status_code == 200
    assert_error(upload(client, b""), 400, "EMPTY_FILE")


def test_path_traversal_filenames_are_ignored(app, client):
    use_ocr(app, text=GENUINE_TEXT)
    response = upload(client, blank(), name="../../../../etc/passwd")
    assert response.status_code == 200
    assert "passwd" not in response.get_data(as_text=True)


# --- 11: OCR failures ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (OcrError("OCR timed out"), 422, "OCR_FAILED"),
        (OcrUnavailableError("missing"), 503, "OCR_UNAVAILABLE"),
        (OcrBusyError("busy"), 503, "OCR_BUSY"),
    ],
)
def test_11_ocr_failures(app, client, error, status, code):
    use_ocr(app, error=error)
    response = upload(client, blank())
    err = assert_error(response, status, code)
    assert "missing" not in err["message"] and "Traceback" not in response.get_data(as_text=True)


def test_ocr_unavailable_is_reported_by_health_and_other_endpoints_still_work(app, client):
    use_ocr(app, available=False, error=OcrUnavailableError("x"))
    assert client.get("/api/health").get_json()["components"]["ocr_engine"] == "not_installed"
    assert client.post("/api/analyze/message", json={"text": "hello"}).status_code == 200


def test_low_ocr_confidence_is_explained_but_never_adds_points(app, client):
    text = "Please share the OTP you just received."
    use_ocr(app, text=text, confidence=41.0)
    body = upload(client, blank()).get_json()
    row = next(i for i in body["indicators"] if i["id"] == "OCR_LOW_CONFIDENCE")
    assert row["source"] == "ocr" and row["weight"] == 0 and row["score_contribution"] == 0
    assert body["confidence"] == "LOW"
    assert "screenshot text was hard to read" in body["analysis"]["low_confidence_reasons"]
    message = client.post("/api/analyze/message", json={"text": text}).get_json()
    assert body["risk_score"] == message["risk_score"]  # OCR itself changes nothing


def test_long_text_is_truncated_and_explained(app, client):
    use_ocr(app, text="Hello there. " * 600)
    body = upload(client, blank()).get_json()
    assert body["analysis"]["ocr"]["truncated"] is True
    assert len(body["analysis"]["ocr"]["extracted_text"]) == 5000
    assert "OCR_TEXT_TRUNCATED" in ids(body, "ocr")


# --- 12-13: URL extraction ----------------------------------------------------------------------
def test_12_urls_are_extracted_including_defanged_ones(app, client):
    use_ocr(app, text="Account suspended. Verify now at hxxps://secure-login-sbi[.]xyz/verify")
    body = upload(client, blank()).get_json()
    link = body["analysis"]["links"][0]
    assert link["url"] == "https://secure-login-sbi.xyz/verify" and link["scored"] is True
    assert body["analysis"]["preprocessing"]["links_deobfuscated"] == 1


def test_13_multiple_urls_only_riskiest_is_scored(app, client):
    use_ocr(
        app,
        text="See https://www.example.com/a and https://hdfcbnak.com/x and http://8.8.8.8/y and https://z.example/",
    )
    body = upload(client, blank()).get_json()
    rows = body["analysis"]["links"]
    assert [r["scored"] for r in rows] == [False, True, False, False]
    assert rows[3]["error"] == "not analysed (limit reached)"


def test_links_in_screenshots_use_the_ssrf_protected_url_analyzer(app, client):
    url = app.extensions["qrguard.url_analysis"]
    url.fetcher = FakeFetcher(
        {"https://bit.ly/p": (302, "http://169.254.169.254/latest/meta-data/")}
    )
    use_ocr(app, text="Claim your refund: https://bit.ly/p")
    body = upload(client, blank()).get_json()
    assert body["analysis"]["links"][0]["redirects"]["status"] == "blocked_private_address"
    assert all(str(r.ip) != "169.254.169.254" for r in url.fetcher.requests)
    assert "169.254" not in str(body)


def test_threat_intel_listing_verifies_a_screenshot(app, client):
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("demo-feed", TIStatus.LISTED)]
    )
    use_ocr(app, text="Details: https://www.example.com/page")
    body = upload(client, blank()).get_json()
    assert body["risk_score"] == 90 and body["verification"]["source"] == "threat_intelligence"


def test_trusted_link_does_not_verify_a_screenshot(app, client):
    use_ocr(app, text="Read more at https://en.wikipedia.org/wiki/Phishing")
    body = upload(client, blank()).get_json()
    assert body["verification"]["status"] == "UNVERIFIED"


# --- 14: privacy ----------------------------------------------------------------------------------
def test_14_ocr_text_is_not_logged_and_no_files_are_written(app, client, caplog):
    use_ocr(app, text="PRIVATE-OCR-MARKER-5521 share the OTP")
    temp_dir = tempfile.gettempdir()
    before = set(os.listdir(temp_dir))
    with caplog.at_level(logging.DEBUG):
        response = upload(client, blank(), name="PRIVATE-FILENAME-3319.png")
    assert response.status_code == 200
    assert "PRIVATE-OCR-MARKER-5521" not in caplog.text
    assert "PRIVATE-FILENAME-3319" not in caplog.text
    assert "PRIVATE-FILENAME-3319" not in response.get_data(as_text=True)
    assert set(os.listdir(temp_dir)) == before


def test_rate_limit_for_screenshots():
    app = build(RATELIMIT_SCREENSHOT="2 per minute")
    client = app.test_client()
    use_ocr(app, text=GENUINE_TEXT)
    assert [upload(client, blank()).status_code for _ in range(2)] == [200, 200]
    assert_error(upload(client, blank()), 429, "RATE_LIMITED")


# --- real Tesseract (end to end) ----------------------------------------------------------------
@real_ocr
def test_real_ocr_scam_screenshot(client):
    body = upload(
        client,
        render_text(
            [
                "Dear customer, your SBI account will be BLOCKED today.",
                "Update your KYC immediately: http://sbi-kyc-update.xyz/login",
            ]
        ),
    ).get_json()
    assert body["risk_level"] == "MALICIOUS" and body["risk_score"] == 65
    assert body["analysis"]["ocr"]["quality"] == "good"
    assert "BRAND_IN_DOMAIN_NAME" in ids(body, "link")


@real_ocr
def test_real_ocr_dark_mode_and_jpeg(client):
    body = upload(
        client,
        render_text(
            ["You received Rs 5000 cashback.", "Enter your UPI PIN to receive the amount."],
            dark=True,
            fmt="JPEG",
        ),
    ).get_json()
    assert body["risk_level"] == "MALICIOUS"
    assert "MSG_UPI_PIN_TO_RECEIVE" in ids(body)


@real_ocr
def test_real_ocr_genuine_screenshot_is_safe(client):
    body = upload(
        client,
        render_text(
            [
                "482913 is your OTP for login. Never share your OTP",
                "with anyone. -HDFC Bank",
            ]
        ),
    ).get_json()
    assert body["risk_level"] == "SAFE"
    assert "MSG_OTP_REQUEST" not in ids(body)


@real_ocr
def test_real_ocr_wrapped_line_keeps_the_sentence_together(client):
    body = upload(
        client, render_text(["Please share the", "OTP you received with our executive."])
    ).get_json()
    assert "MSG_OTP_REQUEST" in ids(body)


@real_ocr
def test_real_ocr_blank_image(client):
    assert_error(upload(client, blank()), 422, "NO_TEXT_FOUND")
