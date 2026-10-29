import pytest

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


PRODUCTION = "https://qrguard.vercel.app"
PREVIEW = "https://qrguard-git-airlock-redesign-develop-qrguard.vercel.app"


def _deployed_client():
    """The production allowlist with one Vercel preview added, as on Render."""
    return make_app(APP_ENV="production", ALLOWED_ORIGINS=f"{PRODUCTION},{PREVIEW}").test_client()


def _preflight(client, origin, path="/api/analyze/message"):
    return client.options(
        path,
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type, Authorization, X-Request-ID",
        },
    )


@pytest.mark.parametrize("origin", [PRODUCTION, PREVIEW])
def test_listed_origins_get_cors_headers_on_health_and_preflight(origin):
    client = _deployed_client()
    health = client.get("/api/health", headers={"Origin": origin})
    assert health.status_code == 200
    assert health.headers["Access-Control-Allow-Origin"] == origin
    assert "Origin" in health.headers.get("Vary", "")  # caches must not reuse it for another origin

    preflight = _preflight(client, origin)
    assert preflight.status_code == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == origin
    assert "POST" in preflight.headers["Access-Control-Allow-Methods"]
    allowed_headers = preflight.headers["Access-Control-Allow-Headers"].lower()
    for header in ("content-type", "authorization", "x-request-id"):
        assert header in allowed_headers
    assert "Access-Control-Allow-Credentials" not in preflight.headers


def test_listed_origin_can_read_results_and_errors():
    client = _deployed_client()
    ok = client.post(
        "/api/analyze/message",
        json={"text": "Your parcel is waiting, pay the fee"},
        headers={"Origin": PREVIEW},
    )
    assert ok.status_code == 200
    assert ok.headers["Access-Control-Allow-Origin"] == PREVIEW
    assert "X-Request-ID" in ok.headers["Access-Control-Expose-Headers"]
    bad = client.post("/api/analyze/message", json={}, headers={"Origin": PREVIEW})
    assert bad.status_code == 400
    assert bad.headers["Access-Control-Allow-Origin"] == PREVIEW  # the page can show the real error


@pytest.mark.parametrize(
    "origin",
    [
        "https://evil.example",
        "http://qrguard-git-airlock-redesign-develop-qrguard.vercel.app",  # wrong scheme
        "https://qrguard-git-airlock-redesign-develop-qrguard.vercel.app.attacker.example",
        "https://attacker-qrguard.vercel.app",
        "https://qrguard-git-other-branch-qrguard.vercel.app",  # other previews stay closed
        "null",
    ],
)
def test_unlisted_origins_get_no_cors_headers(origin):
    client = _deployed_client()
    health = client.get("/api/health", headers={"Origin": origin})
    assert health.status_code == 200  # the server answers; the browser refuses to hand it over
    assert "Access-Control-Allow-Origin" not in health.headers

    preflight = _preflight(client, origin)
    assert "Access-Control-Allow-Origin" not in preflight.headers
    assert "Access-Control-Allow-Methods" not in preflight.headers


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
    # /api/history has only the default limit (503 here: no Firebase configured in tests).
    statuses = [client.get("/api/history").status_code for _ in range(3)]
    assert statuses == [503, 503, 429]


def test_proxy_fix_uses_forwarded_client_ip_for_rate_limits():
    client = make_app(TRUST_PROXY_HOPS="1", RATELIMIT_ANALYZE="1 per minute").test_client()
    body = {"url": "https://example.com"}
    first = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.1"})
    other = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.2"})
    again = client.post("/api/analyze/url", json=body, headers={"X-Forwarded-For": "203.0.113.1"})
    assert (first.status_code, other.status_code, again.status_code) == (200, 200, 429)
