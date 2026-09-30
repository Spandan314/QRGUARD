"""Where history, reports and daily statistics are kept (docs/database-design.md).

Two implementations with the same interface:
    FirestoreHistoryStore  Firebase Cloud Firestore (production), via the Admin SDK
    MemoryHistoryStore     in-process dictionaries: local demos and tests (refused in production)

Records are already privacy-minimised by history_service.py before they reach a store.
"""

from __future__ import annotations

import secrets
import threading
from datetime import UTC, datetime
from typing import Any, Protocol

MAX_BATCH = 500  # Firestore's limit for one batched write


class InvalidCursorError(ValueError):
    """The pagination cursor does not belong to this user's history."""


class HistoryStore(Protocol):
    def get_user(self, uid: str) -> dict[str, Any] | None: ...
    def set_user(self, uid: str, data: dict[str, Any]) -> None: ...
    def delete_user(self, uid: str) -> None: ...
    def add_scan(self, uid: str, record: dict[str, Any]) -> str: ...
    def get_scan(self, uid: str, scan_id: str) -> dict[str, Any] | None: ...
    def list_scans(
        self, uid: str, limit: int, cursor: str | None
    ) -> tuple[list[dict[str, Any]], str | None]: ...
    def delete_scan(self, uid: str, scan_id: str) -> bool: ...
    def delete_all_scans(self, uid: str) -> int: ...
    def delete_expired_scans(self, uid: str, now: datetime) -> int: ...
    def delete_all_expired_scans(self, now: datetime, limit: int) -> int: ...
    def add_report(self, report: dict[str, Any]) -> str: ...
    def list_reports(self, status: str, limit: int) -> list[dict[str, Any]]: ...
    def update_report(self, report_id: str, status: str) -> bool: ...
    def anonymise_reports(self, uid: str) -> int: ...
    def increment_stats(
        self, day: str, input_type: str, level: str, ti_unavailable: bool
    ) -> None: ...
    def get_stats(self, days: list[str]) -> list[dict[str, Any]]: ...


def new_id() -> str:
    return secrets.token_urlsafe(15)


# ------------------------------------------------------------------------------------------------
class MemoryHistoryStore:
    """Thread-safe in-memory store. Data is lost on restart; never used in production."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.users: dict[str, dict[str, Any]] = {}
        self.scans: dict[str, dict[str, dict[str, Any]]] = {}
        self.reports: dict[str, dict[str, Any]] = {}
        self.stats: dict[str, dict[str, Any]] = {}

    def get_user(self, uid: str) -> dict[str, Any] | None:
        with self._lock:
            user = self.users.get(uid)
            return dict(user) if user else None

    def set_user(self, uid: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.users.setdefault(uid, {}).update(data)

    def delete_user(self, uid: str) -> None:
        with self._lock:
            self.users.pop(uid, None)

    def add_scan(self, uid: str, record: dict[str, Any]) -> str:
        scan_id = new_id()
        with self._lock:
            self.scans.setdefault(uid, {})[scan_id] = dict(record)
        return scan_id

    def get_scan(self, uid: str, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            scan = self.scans.get(uid, {}).get(scan_id)
            return {"id": scan_id, **scan} if scan else None

    def list_scans(self, uid: str, limit: int, cursor: str | None):
        with self._lock:
            ordered = sorted(
                self.scans.get(uid, {}).items(), key=lambda kv: kv[1]["created_at"], reverse=True
            )
        if cursor is not None:
            ids = [scan_id for scan_id, _ in ordered]
            if cursor not in ids:
                raise InvalidCursorError
            ordered = ordered[ids.index(cursor) + 1 :]
        page = [{"id": scan_id, **scan} for scan_id, scan in ordered[:limit]]
        next_cursor = page[-1]["id"] if len(ordered) > limit else None
        return page, next_cursor

    def delete_scan(self, uid: str, scan_id: str) -> bool:
        with self._lock:
            return self.scans.get(uid, {}).pop(scan_id, None) is not None

    def delete_all_scans(self, uid: str) -> int:
        with self._lock:
            return len(self.scans.pop(uid, {}))

    def delete_expired_scans(self, uid: str, now: datetime) -> int:
        with self._lock:
            scans = self.scans.get(uid, {})
            expired = [scan_id for scan_id, scan in scans.items() if scan["expire_at"] <= now]
            for scan_id in expired:
                del scans[scan_id]
            return len(expired)

    def delete_all_expired_scans(self, now: datetime, limit: int) -> int:
        deleted = 0
        with self._lock:
            for scans in self.scans.values():
                for scan_id in [s for s, scan in scans.items() if scan["expire_at"] <= now]:
                    if deleted >= limit:
                        return deleted
                    del scans[scan_id]
                    deleted += 1
        return deleted

    def add_report(self, report: dict[str, Any]) -> str:
        report_id = new_id()
        with self._lock:
            self.reports[report_id] = dict(report)
        return report_id

    def list_reports(self, status: str, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            rows = [{"id": rid, **r} for rid, r in self.reports.items() if r["status"] == status]
        return sorted(rows, key=lambda r: r["created_at"], reverse=True)[:limit]

    def update_report(self, report_id: str, status: str) -> bool:
        with self._lock:
            if report_id not in self.reports:
                return False
            self.reports[report_id]["status"] = status
            return True

    def anonymise_reports(self, uid: str) -> int:
        with self._lock:
            mine = [r for r in self.reports.values() if r.get("uid") == uid]
            for report in mine:
                report["uid"] = None
            return len(mine)

    def increment_stats(self, day: str, input_type: str, level: str, ti_unavailable: bool) -> None:
        with self._lock:
            row = self.stats.setdefault(
                day, {"total": 0, "by_level": {}, "by_type": {}, "ti_unavailable": 0}
            )
            row["total"] += 1
            row["by_level"][level] = row["by_level"].get(level, 0) + 1
            row["by_type"][input_type] = row["by_type"].get(input_type, 0) + 1
            row["ti_unavailable"] += int(ti_unavailable)

    def get_stats(self, days: list[str]) -> list[dict[str, Any]]:
        with self._lock:
            return [{"date": day, **self.stats[day]} for day in days if day in self.stats]


# ------------------------------------------------------------------------------------------------
class FirestoreHistoryStore:
    """Cloud Firestore. Collections: users/{uid}, users/{uid}/scans, reports, stats_daily."""

    def __init__(self, client: Any) -> None:
        self.db = client

    def _scans(self, uid: str):
        return self.db.collection("users").document(uid).collection("scans")

    def get_user(self, uid: str) -> dict[str, Any] | None:
        snapshot = self.db.collection("users").document(uid).get()
        return snapshot.to_dict() if snapshot.exists else None

    def set_user(self, uid: str, data: dict[str, Any]) -> None:
        self.db.collection("users").document(uid).set(data, merge=True)

    def delete_user(self, uid: str) -> None:
        self.db.collection("users").document(uid).delete()

    def add_scan(self, uid: str, record: dict[str, Any]) -> str:
        ref = self._scans(uid).document(new_id())
        ref.set(record)
        return ref.id

    def get_scan(self, uid: str, scan_id: str) -> dict[str, Any] | None:
        snapshot = self._scans(uid).document(scan_id).get()
        return {"id": snapshot.id, **snapshot.to_dict()} if snapshot.exists else None

    def list_scans(self, uid: str, limit: int, cursor: str | None):
        from google.cloud.firestore import Query

        query = self._scans(uid).order_by("created_at", direction=Query.DESCENDING)
        if cursor is not None:
            start = self._scans(uid).document(cursor).get()
            if not start.exists:
                raise InvalidCursorError
            query = query.start_after(start)
        snapshots = list(query.limit(limit + 1).stream())
        page = [{"id": s.id, **s.to_dict()} for s in snapshots[:limit]]
        next_cursor = page[-1]["id"] if len(snapshots) > limit else None
        return page, next_cursor

    def delete_scan(self, uid: str, scan_id: str) -> bool:
        ref = self._scans(uid).document(scan_id)
        if not ref.get().exists:
            return False
        ref.delete()
        return True

    def delete_all_scans(self, uid: str) -> int:
        deleted = 0
        while True:
            docs = list(self._scans(uid).limit(MAX_BATCH).stream())
            if not docs:
                return deleted
            batch = self.db.batch()
            for doc in docs:
                batch.delete(doc.reference)
            batch.commit()
            deleted += len(docs)

    def _delete_query(self, query: Any, limit: int) -> int:
        """Delete the documents a query returns, in batches, up to `limit` documents."""
        deleted = 0
        while deleted < limit:
            docs = list(query.limit(min(MAX_BATCH, limit - deleted)).stream())
            if not docs:
                break
            batch = self.db.batch()
            for doc in docs:
                batch.delete(doc.reference)
            batch.commit()
            deleted += len(docs)
        return deleted

    def delete_expired_scans(self, uid: str, now: datetime) -> int:
        from google.cloud.firestore import FieldFilter

        query = self._scans(uid).where(filter=FieldFilter("expire_at", "<=", now))
        return self._delete_query(query, 10_000)

    def delete_all_expired_scans(self, now: datetime, limit: int) -> int:
        # Collection-group query over every user's scans; needs the collection-group index on
        # scans.expire_at declared in firebase/firestore.indexes.json.
        from google.cloud.firestore import FieldFilter

        query = self.db.collection_group("scans").where(filter=FieldFilter("expire_at", "<=", now))
        return self._delete_query(query, limit)

    def add_report(self, report: dict[str, Any]) -> str:
        ref = self.db.collection("reports").document(new_id())
        ref.set(report)
        return ref.id

    def list_reports(self, status: str, limit: int) -> list[dict[str, Any]]:
        from google.cloud.firestore import FieldFilter, Query

        query = (
            self.db.collection("reports")
            .where(filter=FieldFilter("status", "==", status))
            .order_by("created_at", direction=Query.DESCENDING)
            .limit(limit)
        )
        return [{"id": s.id, **s.to_dict()} for s in query.stream()]

    def update_report(self, report_id: str, status: str) -> bool:
        ref = self.db.collection("reports").document(report_id)
        if not ref.get().exists:
            return False
        ref.update({"status": status})
        return True

    def anonymise_reports(self, uid: str) -> int:
        from google.cloud.firestore import FieldFilter

        docs = list(
            self.db.collection("reports").where(filter=FieldFilter("uid", "==", uid)).stream()
        )
        for start in range(0, len(docs), MAX_BATCH):
            batch = self.db.batch()
            for doc in docs[start : start + MAX_BATCH]:
                batch.update(doc.reference, {"uid": None})
            batch.commit()
        return len(docs)

    def increment_stats(self, day: str, input_type: str, level: str, ti_unavailable: bool) -> None:
        from google.cloud.firestore import Increment

        self.db.collection("stats_daily").document(day).set(
            {
                "total": Increment(1),
                "by_level": {level: Increment(1)},
                "by_type": {input_type: Increment(1)},
                "ti_unavailable": Increment(int(ti_unavailable)),
            },
            merge=True,
        )

    def get_stats(self, days: list[str]) -> list[dict[str, Any]]:
        refs = [self.db.collection("stats_daily").document(day) for day in days]
        rows = []
        for snapshot in self.db.get_all(refs):
            if snapshot.exists:
                rows.append({"date": snapshot.id, **snapshot.to_dict()})
        return sorted(rows, key=lambda r: r["date"])


def utcnow() -> datetime:
    return datetime.now(UTC)
