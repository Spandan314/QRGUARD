"""Stub endpoints validate the real contract, then answer 501 until each module exists."""

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
def test_valid_json_requests_reach_the_module_stub(client, path, body):
    assert_error(client.post(path, json=body), 501, "NOT_IMPLEMENTED")


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


@pytest.mark.parametrize("path", ["/api/analyze/screenshot", "/api/analyze/qr"])
def test_multipart_upload_reaches_stub(client, path):
    response = client.post(
        path,
        data={"file": (io.BytesIO(b"\x89PNG\r\n\x1a\n"), "shot.png")},
        content_type="multipart/form-data",
    )
    assert_error(response, 501, "NOT_IMPLEMENTED")


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
