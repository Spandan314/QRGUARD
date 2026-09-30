"""API contract: every endpoint validates its input the same way (all are now implemented)."""

import io

import pytest

from tests.integration.test_errors import assert_error


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/analyze/qr", {"content": "upi://pay?pa=demo@upi", "source": "camera"}),
        ("/api/generate/qr", {"type": "url", "data": {"url": "https://example.com"}}),
    ],
)
def test_valid_json_requests_are_processed(client, path, body):
    # Formerly 501 stubs; both endpoints are implemented now.
    response = client.post(path, json=body)
    assert response.status_code == 200
    assert response.get_json()["request_id"] == response.headers["X-Request-ID"]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/analyze/url", {}),
        ("/api/analyze/url", {"url": ""}),
        ("/api/analyze/message", {"text": "a" * 5001}),
        ("/api/analyze/qr", {"content": "x", "source": "satellite"}),
        ("/api/generate/qr", {"type": "bitcoin", "data": {"x": "y"}}),
        ("/api/generate/qr", {"type": "url", "data": {"url": "x"}, "size": 5000}),
    ],
)
def test_invalid_json_requests_rejected(client, path, body):
    assert_error(client.post(path, json=body), 400, "VALIDATION_ERROR")


def test_qr_image_endpoint_validates_images(client):
    # Formerly a 501 stub; the truncated PNG header is now rejected by real validation.
    response = client.post(
        "/api/analyze/qr",
        data={"file": (io.BytesIO(b"\x89PNG\r\n\x1a\n"), "shot.png")},
        content_type="multipart/form-data",
    )
    assert_error(response, 422, "UNPROCESSABLE_IMAGE")


def test_screenshot_endpoint_is_implemented_and_validates_images(client):
    # Formerly a 501 stub; now the (truncated) PNG header is rejected by real validation.
    response = client.post(
        "/api/analyze/screenshot",
        data={"file": (io.BytesIO(b"\x89PNG\r\n\x1a\n"), "shot.png")},
        content_type="multipart/form-data",
    )
    assert_error(response, 422, "UNPROCESSABLE_IMAGE")


def test_screenshot_without_file_400(client):
    response = client.post(
        "/api/analyze/screenshot", data={"other": "x"}, content_type="multipart/form-data"
    )
    assert_error(response, 400, "MISSING_FILE")


def test_screenshot_as_json_415(client):
    assert_error(
        client.post("/api/analyze/screenshot", json={"a": 1}), 415, "UNSUPPORTED_MEDIA_TYPE"
    )


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/api/history"), ("delete", "/api/history"), ("delete", "/api/history/abc123")],
)
def test_history_stubs(client, method, path):
    assert_error(getattr(client, method)(path), 501, "NOT_IMPLEMENTED")
