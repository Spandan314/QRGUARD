"""Every error must use the standard JSON envelope and never leak internals."""


def assert_error(response, status, code):
    assert response.status_code == status
    assert response.is_json
    error = response.get_json()["error"]
    assert error["code"] == code
    assert error["message"]
    assert error["request_id"] == response.headers["X-Request-ID"]
    return error


def test_unknown_route_404(client):
    assert_error(client.get("/api/does-not-exist"), 404, "NOT_FOUND")


def test_wrong_method_405_keeps_allow_header(client):
    response = client.get("/api/analyze/url")
    assert_error(response, 405, "METHOD_NOT_ALLOWED")
    assert "POST" in response.headers["Allow"]


def test_wrong_content_type_415(client):
    response = client.post("/api/analyze/url", data="url=http://x", content_type="text/plain")
    assert_error(response, 415, "UNSUPPORTED_MEDIA_TYPE")


def test_malformed_json_400(client):
    response = client.post("/api/analyze/url", data="{not json", content_type="application/json")
    assert_error(response, 400, "INVALID_JSON")


def test_json_array_instead_of_object_400(client):
    assert_error(client.post("/api/analyze/url", json=["http://x"]), 400, "INVALID_JSON")


def test_validation_error_lists_fields_without_echoing_input(client):
    secret_like = "my-private-text-" + "x" * 3000
    response = client.post("/api/analyze/url", json={"url": secret_like})
    error = assert_error(response, 400, "VALIDATION_ERROR")
    assert error["details"][0]["field"] == "url"
    assert "my-private-text" not in response.get_data(as_text=True)


def test_unknown_field_rejected(client):
    error = assert_error(
        client.post("/api/analyze/url", json={"url": "http://x", "URL": "y"}),
        400,
        "VALIDATION_ERROR",
    )
    assert any(item["field"] == "URL" for item in error["details"])


def test_wrong_type_rejected(client):
    assert_error(
        client.post("/api/analyze/url", json={"url": "http://x", "save_to_history": "yes"}),
        400,
        "VALIDATION_ERROR",
    )


def test_json_body_over_limit_413(client):
    response = client.post("/api/analyze/message", json={"text": "a" * (70 * 1024)})
    assert_error(response, 413, "PAYLOAD_TOO_LARGE")


def test_upload_over_max_content_length_413():
    import io

    from tests.conftest import make_app

    client = make_app(MAX_UPLOAD_MB="1").test_client()
    big = io.BytesIO(b"\x89PNG" + b"0" * (1024 * 1024 + 10))
    response = client.post(
        "/api/analyze/screenshot",
        data={"file": (big, "big.png")},
        content_type="multipart/form-data",
    )
    assert_error(response, 413, "PAYLOAD_TOO_LARGE")


def test_unexpected_exception_returns_generic_500_without_traceback():
    from tests.conftest import make_app

    app = make_app()

    @app.get("/api/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    response = app.test_client().get("/api/boom")
    assert_error(response, 500, "INTERNAL_ERROR")
    text = response.get_data(as_text=True)
    assert "hunter2" not in text and "Traceback" not in text
