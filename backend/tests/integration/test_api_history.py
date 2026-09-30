"""Sign-in, history, reports and admin (in-memory store + dev tokens; no Firebase needed)."""

import logging
from datetime import timedelta

import pytest

from app.config import Config, ConfigError
from app.services.history_store import utcnow
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeOcrEngine, FakeResolver
from tests.images import blank, qr_png
from tests.integration.test_errors import assert_error

ALICE = {"Authorization": "Bearer dev-alice"}
BOB = {"Authorization": "Bearer dev-bob"}
ADMIN = {"Authorization": "Bearer dev-admin-root"}
SCAM_TEXT = (
    "Dear customer, your SBI account will be BLOCKED today. Share the OTP and update your KYC "
    "immediately: http://sbi-kyc-update.xyz/login?token=SECRET123"
)


@pytest.fixture
def app():
    app = make_app(HISTORY_STORE="memory", AUTH_DEV_TOKENS="true")
    service = app.extensions["qrguard.url_analysis"]
    service.resolver = FakeResolver()
    service.fetcher = FakeFetcher()
    return app


@pytest.fixture
def client(app):
    return app.test_client()


def analyze_url(client, url="http://sbi-kyc-update.xyz/login?session=abc", headers=None, save=True):
    return client.post(
        "/api/analyze/url", json={"url": url, "save_to_history": save}, headers=headers or {}
    )


def history(client, headers=ALICE, **params):
    response = client.get("/api/history", query_string=params, headers=headers)
    assert response.status_code == 200, response.get_json()
    return response.get_json()


# --- analysis with and without sign-in -----------------------------------------------------------
def test_anonymous_analysis_is_unchanged(client):
    body = analyze_url(client, save=False).get_json()
    assert body["risk_level"] in ("SUSPICIOUS", "MALICIOUS") and "history" not in body


def test_saving_needs_sign_in(client):
    body = analyze_url(client).get_json()
    assert body["history"] == {"saved": False, "reason": "sign_in_required"}


@pytest.mark.parametrize(
    "header",
    ["Bearer nonsense", "Bearer dev-a", "Basic dev-alice", "Bearer ", "Bearer " + "x" * 5000],
)
def test_invalid_token_on_analysis_is_rejected(client, header):
    response = analyze_url(client, headers={"Authorization": header})
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_TOKEN"


def test_saved_url_scan_is_privacy_minimised(client):
    body = analyze_url(client, headers=ALICE).get_json()
    assert body["history"]["saved"] is True
    item = history(client)["items"][0]
    assert item["id"] == body["history"]["scan_id"]
    assert item["input_type"] == "url" and item["risk_score"] == body["risk_score"]
    assert item["target"]["kind"] == "url" and item["target"]["domain"] == "sbi-kyc-update.xyz"
    assert len(item["target"]["url_hash"]) == 64
    text = str(item)
    assert "session=abc" not in text and "/login" not in text  # no full URL, path or query
    assert all("evidence" not in i and "message" not in i for i in item["indicators"])
    assert "expire_at" not in item and "created_at" in item


def test_message_scan_never_stores_the_text(client):
    body = client.post(
        "/api/analyze/message", json={"text": SCAM_TEXT, "save_to_history": True}, headers=ALICE
    ).get_json()
    assert body["history"]["saved"] is True
    item = history(client)["items"][0]
    assert item["target"] == {"kind": "message", "length": len(SCAM_TEXT), "url_count": 1}
    # Fragments that exist only in the user's text (indicator titles are fixed config strings).
    for fragment in ("SECRET123", "Dear customer", "update your KYC", "sbi-kyc-update"):
        assert fragment not in str(item)


def test_screenshot_and_qr_scans(app, client):
    app.extensions["qrguard.screenshot_analysis"].ocr_engine = FakeOcrEngine(text=SCAM_TEXT)
    shot = client.post(
        "/api/analyze/screenshot",
        data={"file": (_png(blank()), "s.png"), "save_to_history": "true"},
        headers=ALICE,
    ).get_json()
    assert shot["history"]["saved"] is True
    upi = client.post(
        "/api/analyze/qr",
        json={
            "content": "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund",
            "save_to_history": True,
        },
        headers=ALICE,
    ).get_json()
    wifi = client.post(
        "/api/analyze/qr",
        data={
            "file": (_png(qr_png("WIFI:T:WPA;S:Cafe;P:Zq9SECRETpw;;")), "q.png"),
            "save_to_history": "true",
        },
        headers=ALICE,
    ).get_json()
    assert upi["history"]["saved"] and wifi["history"]["saved"]
    items = {i["input_type"]: i for i in history(client)["items"]}
    assert items["screenshot"]["target"]["kind"] == "screenshot"
    assert items["qr_camera"]["target"] == {"kind": "upi", "payee_domain": "@okdemo"}
    assert items["qr_image"]["target"] == {"kind": "wifi"}
    everything = str(items)
    assert "refund.desk9912" not in everything and "Zq9SECRETpw" not in everything
    assert "SECRET123" not in everything


def _png(data):
    import io

    return io.BytesIO(data)


def test_history_setting_can_be_switched_off(client):
    assert client.get("/api/me", headers=ALICE).get_json()["save_history"] is True
    updated = client.patch("/api/me", json={"save_history": False}, headers=ALICE).get_json()
    assert updated["save_history"] is False
    body = analyze_url(client, headers=ALICE).get_json()
    assert body["history"] == {"saved": False, "reason": "history_disabled"}
    assert history(client)["items"] == []


def test_settings_validation(client):
    assert_error(
        client.patch("/api/me", json={"save_history": "no"}, headers=ALICE), 400, "VALIDATION_ERROR"
    )
    assert_error(
        client.patch("/api/me", json={"admin": True}, headers=ALICE), 400, "VALIDATION_ERROR"
    )


# --- listing, isolation, deletion ---------------------------------------------------------------
def test_pagination(client):
    for n in range(3):
        analyze_url(client, url=f"https://example{n}.com/", headers=ALICE)
    first = history(client, limit=2)
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = history(client, limit=2, cursor=first["next_cursor"])
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    ids = [i["id"] for i in first["items"] + second["items"]]
    assert len(set(ids)) == 3


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 51}, {"limit": "x"}, {"cursor": "../x"}, {"cursor": "unknownCursor1"}],
)
def test_invalid_listing_parameters(client, params):
    analyze_url(client, headers=ALICE)
    response = client.get("/api/history", query_string=params, headers=ALICE)
    assert_error(response, 400, "VALIDATION_ERROR")


def test_users_only_see_and_delete_their_own_scans(client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    assert history(client, headers=BOB)["items"] == []
    assert_error(client.get(f"/api/history/{scan_id}", headers=BOB), 404, "NOT_FOUND")
    assert_error(client.delete(f"/api/history/{scan_id}", headers=BOB), 404, "NOT_FOUND")
    assert client.get(f"/api/history/{scan_id}", headers=ALICE).status_code == 200


def test_delete_one_and_all(client):
    ids = [analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"] for _ in range(3)]
    assert client.delete(f"/api/history/{ids[0]}", headers=ALICE).status_code == 204
    assert_error(client.delete(f"/api/history/{ids[0]}", headers=ALICE), 404, "NOT_FOUND")
    assert_error(client.delete("/api/history/bad id!", headers=ALICE), 404, "NOT_FOUND")
    assert client.delete("/api/history", headers=ALICE).get_json() == {"deleted": 2}
    assert history(client)["items"] == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/api/history"),
        ("delete", "/api/history"),
        ("get", "/api/me"),
        ("post", "/api/reports"),
    ],
)
def test_protected_routes_need_a_token(client, method, path):
    assert_error(getattr(client, method)(path), 401, "AUTH_REQUIRED")
    response = getattr(client, method)(path, headers={"Authorization": "Bearer expired"})
    assert_error(response, 401, "INVALID_TOKEN")


def test_delete_my_data(client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    client.post("/api/reports", json={"reported_as": "scam", "scan_id": scan_id}, headers=ALICE)
    result = client.delete("/api/me", headers=ALICE).get_json()
    assert result == {"deleted_scans": 1, "anonymised_reports": 1, "account_deleted": False}
    assert history(client)["items"] == []


# --- retention without Firestore TTL (free Spark plan) --------------------------------------------
def expire(app, uid, scan_id):
    """Make a stored scan look older than the retention period."""
    store = app.extensions["qrguard.history"].store
    store.scans[uid][scan_id]["expire_at"] = utcnow() - timedelta(seconds=1)


def test_expired_scans_are_hidden_and_deleted_when_history_is_opened(app, client):
    old = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    kept = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", old)
    assert_error(client.get(f"/api/history/{old}", headers=ALICE), 404, "NOT_FOUND")
    assert [item["id"] for item in history(client)["items"]] == [kept]
    assert old not in app.extensions["qrguard.history"].store.scans["dev-alice"]  # really deleted
    assert client.get(f"/api/history/{kept}", headers=ALICE).status_code == 200


def test_expired_scans_are_deleted_at_sign_in(app, client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", scan_id)
    assert client.get("/api/me", headers=ALICE).status_code == 200  # the apps load this at sign-in
    assert app.extensions["qrguard.history"].store.scans["dev-alice"] == {}


def test_an_expired_scan_cannot_be_reported(app, client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", scan_id)
    response = client.post(
        "/api/reports", json={"reported_as": "scam", "scan_id": scan_id}, headers=ALICE
    )
    assert_error(response, 404, "NOT_FOUND")


def test_a_failed_purge_still_hides_expired_scans(app, client, caplog, monkeypatch):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", scan_id)
    store = app.extensions["qrguard.history"].store

    def broken(uid, now):
        raise RuntimeError("firestore down")

    monkeypatch.setattr(store, "delete_expired_scans", broken)
    with caplog.at_level(logging.WARNING):
        assert history(client)["items"] == []
        assert client.get("/api/me", headers=ALICE).status_code == 200
    assert "expired-history purge failed" in caplog.text


def test_admin_purges_every_users_expired_scans(app, client):
    alice_old = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    bob_old = analyze_url(client, headers=BOB).get_json()["history"]["scan_id"]
    bob_new = analyze_url(client, headers=BOB).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", alice_old)
    expire(app, "dev-bob", bob_old)
    response = client.post("/api/admin/history/purge-expired", headers=ADMIN)
    assert response.status_code == 200 and response.get_json() == {"deleted": 2}
    scans = app.extensions["qrguard.history"].store.scans
    assert scans["dev-alice"] == {} and list(scans["dev-bob"]) == [bob_new]


def test_purge_command(app, client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    expire(app, "dev-alice", scan_id)
    result = app.test_cli_runner().invoke(args=["purge-expired-history"])
    assert result.exit_code == 0 and "Deleted 1 expired scan(s)." in result.output
    result = app.test_cli_runner().invoke(args=["purge-expired-history"])
    assert "Deleted 0 expired scan(s)." in result.output


def test_purge_command_needs_history():
    result = make_app().test_cli_runner().invoke(args=["purge-expired-history"])
    assert result.exit_code != 0 and "History is not configured" in result.output


# --- reports and admin ---------------------------------------------------------------------------
def test_reports(client):
    scan_id = analyze_url(client, headers=ALICE).get_json()["history"]["scan_id"]
    created = client.post(
        "/api/reports",
        json={"reported_as": "false_positive", "note": "My bank's real domain", "scan_id": scan_id},
        headers=ALICE,
    )
    assert created.status_code == 201 and created.get_json()["id"]
    other = client.post(
        "/api/reports", json={"reported_as": "scam", "scan_id": scan_id}, headers=BOB
    )
    assert_error(other, 404, "NOT_FOUND")
    standalone = client.post("/api/reports", json={"reported_as": "scam"}, headers=BOB)
    assert standalone.status_code == 201


@pytest.mark.parametrize(
    "body",
    [
        {"reported_as": "spam"},
        {"reported_as": "scam", "note": "x" * 281},
        {"reported_as": "scam", "scan_id": "../../x"},
        {"reported_as": "scam", "uid": "x"},
    ],
)
def test_report_validation(client, body):
    assert_error(client.post("/api/reports", json=body, headers=ALICE), 400, "VALIDATION_ERROR")


def test_admin_requires_the_admin_claim(client):
    for method, path in (
        ("get", "/api/admin/stats"),
        ("get", "/api/admin/reports"),
        ("patch", "/api/admin/reports/abcdefgh12"),
        ("post", "/api/admin/history/purge-expired"),
    ):
        assert_error(getattr(client, method)(path, json={}, headers=ALICE), 403, "FORBIDDEN")
        assert_error(getattr(client, method)(path, json={}), 401, "AUTH_REQUIRED")


def test_admin_stats_are_anonymous_counts(client):
    analyze_url(client, save=False)  # anonymous analyses are counted too
    analyze_url(client, url="https://www.wikipedia.org/", headers=ALICE)
    body = client.get("/api/admin/stats?days=7", headers=ADMIN).get_json()
    today = body["days"][-1]
    assert today["total"] == 2 and today["by_type"] == {"url": 2}
    assert sum(today["by_level"].values()) == 2
    assert "alice" not in str(body)
    assert {"provider": "local_feed", "enabled": True, "external": False} in body["threat_intel"]
    assert_error(client.get("/api/admin/stats?days=0", headers=ADMIN), 400, "VALIDATION_ERROR")


def test_admin_reviews_reports_without_seeing_reporters(client):
    report_id = client.post(
        "/api/reports", json={"reported_as": "scam", "note": "fake SBI"}, headers=ALICE
    ).get_json()["id"]
    items = client.get("/api/admin/reports?status=open", headers=ADMIN).get_json()["items"]
    assert [r["id"] for r in items] == [report_id]
    assert "uid" not in items[0] and items[0]["note"] == "fake SBI"
    patched = client.patch(
        f"/api/admin/reports/{report_id}", json={"status": "reviewed"}, headers=ADMIN
    )
    assert patched.get_json() == {"id": report_id, "status": "reviewed"}
    assert client.get("/api/admin/reports?status=open", headers=ADMIN).get_json()["items"] == []
    assert_error(
        client.patch("/api/admin/reports/unknownid1", json={"status": "reviewed"}, headers=ADMIN),
        404,
        "NOT_FOUND",
    )
    assert_error(
        client.get("/api/admin/reports?status=all", headers=ADMIN), 400, "VALIDATION_ERROR"
    )


# --- rate limits, failures, privacy, configuration ---------------------------------------------
def test_signed_in_users_are_limited_per_uid():
    app = make_app(
        HISTORY_STORE="memory",
        AUTH_DEV_TOKENS="true",
        RATELIMIT_ANALYZE="1 per minute",
        RATELIMIT_ANALYZE_AUTH="2 per minute",
    )
    client = app.test_client()
    body = {"url": "https://example.com/"}
    alice = [
        client.post("/api/analyze/url", json=body, headers=ALICE).status_code for _ in range(3)
    ]
    assert alice == [200, 200, 429]
    assert client.post("/api/analyze/url", json=body, headers=BOB).status_code == 200  # own bucket
    assert client.post("/api/analyze/url", json=body).status_code == 200  # IP bucket


def test_store_failures_never_break_the_analysis(app, client, caplog):
    store = app.extensions["qrguard.history"].store

    def boom(*args, **kwargs):
        raise RuntimeError("firestore down")

    store.add_scan = boom
    store.increment_stats = boom
    response = analyze_url(client, headers=ALICE)
    assert response.status_code == 200
    assert response.get_json()["history"] == {"saved": False, "reason": "history_error"}
    assert "firestore down" not in caplog.text


def test_tokens_and_content_are_never_logged(client, caplog):
    caplog.set_level(logging.DEBUG)
    client.post(
        "/api/analyze/message", json={"text": SCAM_TEXT, "save_to_history": True}, headers=ALICE
    )
    assert "dev-alice" not in caplog.text and "SECRET123" not in caplog.text


def test_history_unavailable_without_a_store():
    client = make_app(AUTH_DEV_TOKENS="true").test_client()
    assert_error(client.get("/api/history", headers=ALICE), 503, "SERVICE_UNAVAILABLE")
    body = client.post(
        "/api/analyze/url", json={"url": "https://a.com", "save_to_history": True}, headers=ALICE
    ).get_json()
    assert body["history"] == {"saved": False, "reason": "history_unavailable"}


def test_store_without_any_sign_in_method_is_disabled():
    app = make_app(HISTORY_STORE="memory")
    assert app.extensions["qrguard.history"].enabled is False


@pytest.mark.parametrize(
    ("env", "message"),
    [
        (
            {
                "APP_ENV": "production",
                "ALLOWED_ORIGINS": "https://a.app",
                "AUTH_DEV_TOKENS": "true",
            },
            "not allowed in production",
        ),
        (
            {
                "APP_ENV": "production",
                "ALLOWED_ORIGINS": "https://a.app",
                "HISTORY_STORE": "memory",
            },
            "not allowed in production",
        ),
        ({"HISTORY_STORE": "firestore"}, "needs FIREBASE_PROJECT_ID"),
        ({"FIREBASE_PROJECT_ID": "Bad Project!"}, "FIREBASE_PROJECT_ID"),
        ({"HISTORY_STORE": "sql"}, "HISTORY_STORE"),
    ],
)
def test_unsafe_or_invalid_configuration_is_refused(env, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env)


def test_credentials_are_not_in_config_repr():
    config = Config.from_env({"FIREBASE_CREDENTIALS_JSON": '{"private_key": "SUPERSECRET"}'})
    assert "SUPERSECRET" not in repr(config)
