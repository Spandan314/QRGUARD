def test_health_ok(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    body = response.get_json()
    assert body["status"] == "ok"
    assert body["service"] == "qrguard-backend"
    assert body["components"]["scoring_config"]["thresholds"] == {"suspicious": 30, "malicious": 60}
    assert body["components"]["ocr_engine"] in ("available", "not_installed")


def test_health_has_request_id_and_security_headers(client):
    response = client.get("/api/health")
    assert len(response.headers["X-Request-ID"]) >= 8
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in response.headers  # only in production


def test_hsts_in_production():
    from tests.conftest import make_app

    app = make_app(APP_ENV="production", ALLOWED_ORIGINS="https://qrguard.example")
    response = app.test_client().get("/api/health")
    assert "max-age" in response.headers["Strict-Transport-Security"]


def test_valid_client_request_id_is_echoed(client):
    response = client.get("/api/health", headers={"X-Request-ID": "postman-test-0001"})
    assert response.headers["X-Request-ID"] == "postman-test-0001"


def test_unsafe_client_request_id_is_replaced(client):
    response = client.get("/api/health", headers={"X-Request-ID": "bad id <script>"})
    assert response.headers["X-Request-ID"] != "bad id <script>"
