"""MemoryHistoryStore retention helpers (the Firestore versions run against the emulator)."""

from datetime import timedelta

from app.services.history_store import MemoryHistoryStore, utcnow


def _scan(expire_at):
    return {"created_at": utcnow(), "expire_at": expire_at}


def test_expired_scans_are_deleted_per_user_and_in_chunks_for_everyone():
    store = MemoryHistoryStore()
    now = utcnow()
    past, future = now - timedelta(seconds=1), now + timedelta(days=1)
    kept = store.add_scan("alice", _scan(future))
    store.add_scan("alice", _scan(past))
    for _ in range(3):
        store.add_scan("bob", _scan(past))

    assert store.delete_expired_scans("alice", now) == 1
    assert list(store.scans["alice"]) == [kept]
    assert store.delete_expired_scans("nobody", now) == 0
    assert store.delete_all_expired_scans(now, limit=2) == 2
    assert store.delete_all_expired_scans(now, limit=2) == 1
    assert store.delete_all_expired_scans(now, limit=2) == 0
    assert store.scans["bob"] == {} and list(store.scans["alice"]) == [kept]


def test_firestore_index_config_deploys_on_the_free_spark_plan():
    """Spark rejects every field override (TTL or single-field index) with "billing disabled".

    The retention queries use only Firestore's automatic single-field indexes, so the deployed
    configuration must contain no field overrides at all.
    """
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[3] / "firebase" / "firestore.indexes.json"
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["fieldOverrides"] == []
    assert "ttl" not in json.dumps(config)
