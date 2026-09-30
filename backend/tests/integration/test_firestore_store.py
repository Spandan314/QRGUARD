"""FirestoreHistoryStore against the real Firestore emulator.

Run with the emulator (no Google account needed):
    cd firebase && npm ci && npm run test:backend
These tests are skipped when FIRESTORE_EMULATOR_HOST is not set.
"""

import os
import uuid

import pytest

from app.services.history_store import FirestoreHistoryStore, InvalidCursorError, utcnow
from tests.conftest import make_app

pytestmark = [
    pytest.mark.firestore_emulator,
    pytest.mark.skipif(
        not os.environ.get("FIRESTORE_EMULATOR_HOST"), reason="Firestore emulator not running"
    ),
]
PROJECT = "demo-qrguard"


@pytest.fixture
def store():
    from google.auth.credentials import AnonymousCredentials
    from google.cloud import firestore

    return FirestoreHistoryStore(
        firestore.Client(project=PROJECT, credentials=AnonymousCredentials())
    )


def uid():
    return f"test-{uuid.uuid4().hex[:12]}"


def record(score):
    return {
        "risk_score": score,
        "risk_level": "SAFE",
        "created_at": utcnow(),
        "target": {"kind": "url"},
    }


def test_scans_crud_and_pagination(store):
    user = uid()
    ids = [store.add_scan(user, record(n)) for n in range(5)]
    page1, cursor = store.list_scans(user, 2, None)
    assert [p["risk_score"] for p in page1] == [4, 3] and cursor == page1[-1]["id"]
    page2, cursor2 = store.list_scans(user, 2, cursor)
    page3, cursor3 = store.list_scans(user, 2, cursor2)
    assert [p["risk_score"] for p in page2 + page3] == [2, 1, 0] and cursor3 is None
    with pytest.raises(InvalidCursorError):
        store.list_scans(user, 2, "doesNotExist1")
    assert store.get_scan(user, ids[0])["risk_score"] == 0
    assert store.get_scan(uid(), ids[0]) is None  # other users cannot see it
    assert store.delete_scan(user, ids[0]) is True and store.delete_scan(user, ids[0]) is False
    assert store.delete_all_scans(user) == 4
    assert store.list_scans(user, 10, None) == ([], None)


def test_users_reports_and_stats(store):
    user = uid()
    assert store.get_user(user) is None
    store.set_user(user, {"save_history": True})
    store.set_user(user, {"save_history": False})
    assert store.get_user(user) == {"save_history": False}
    store.delete_user(user)
    assert store.get_user(user) is None

    report_id = store.add_report(
        {"uid": user, "status": "open", "created_at": utcnow(), "note": "x"}
    )
    assert report_id in [r["id"] for r in store.list_reports("open", 50)]
    assert store.update_report(report_id, "reviewed") is True
    assert store.update_report("missingReport1", "reviewed") is False
    assert store.anonymise_reports(user) == 1

    day = f"2099-01-{uuid.uuid4().int % 28 + 1:02d}"
    store.increment_stats(day, "url", "SAFE", False)
    store.increment_stats(day, "qr_camera", "MALICIOUS", True)
    [row] = store.get_stats([day, "2099-12-31"])
    assert row["total"] >= 2 and row["by_type"]["qr_camera"] >= 1 and row["ti_unavailable"] >= 1


def test_api_end_to_end_with_firestore():
    app = make_app(FIREBASE_PROJECT_ID=PROJECT, HISTORY_STORE="firestore", AUTH_DEV_TOKENS="true")
    client = app.test_client()
    headers = {"Authorization": f"Bearer dev-{uuid.uuid4().hex[:10]}"}
    body = client.post(
        "/api/analyze/url",
        json={"url": "https://www.wikipedia.org/", "save_to_history": True},
        headers=headers,
    ).get_json()
    assert body["history"]["saved"] is True
    items = client.get("/api/history", headers=headers).get_json()["items"]
    assert [i["id"] for i in items] == [body["history"]["scan_id"]]
    assert items[0]["target"]["domain"] == "wikipedia.org"
    assert client.delete("/api/history", headers=headers).get_json() == {"deleted": 1}
