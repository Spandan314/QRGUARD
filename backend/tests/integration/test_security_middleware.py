from tests.conftest import make_app
from tests.integration.test_errors import assert_error


def test_cors_allows_configured_origin(client):
    response = client.options(
        "/api/analyze/url",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization",
        },
    )
    assert response.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"
    assert "Access-Control-Allow-Credentials" not in response.headers


def test_cors_blocks_unknown_origin(client):
    response = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in response.headers


def test_rate_limit_returns_429_with_retry_after():
    client = make_app(RATELIMIT_ANALYZE="3 per minute").test_client()
    body = {"url": "https://example.com"}
    statuses = [client.post("/api/analyze/url", json=body).status_code for _ in range(3)]
    assert statuses == [200, 200, 200]

    response = client.post("/api/analyze/url", json=body)
    assert_error(response, 429, "RATE_LIMITED")
    assert int(response.headers["Retry-After"]) > 0


def test_health_is_exempt_from_rate_limit():
    client = make_app(RATELIMIT_DEFAULT="2 per minute").test_client()
    assert all(client.get("/api/health").status_code == 200 for _ in range(5))


def test_default_limit_applies_to_other_routes():
    client = make_app(RATELIMIT_DEFAULT="2 per minute").test_client()
    statuses = [client.get("/api/history").status_code for _ in range(3)]
    assert statuses == [501, 501, 429]


def test_proxy_fix_uses_forwarded_client_ip_for_rate_limits():
    client = make_app(TRUST_PROXY_HOPS="1", RATELIMIT_ANALYZE="1 per minute").test_client()
    body = {"url": "https://example.com"}
    first = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.1"})
    other = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.2"})
    again = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.1"})
    assert (first.status_code, other.status_code, again.status_code) == (200, 200, 429)
