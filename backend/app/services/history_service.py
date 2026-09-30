"""History, reports and statistics on top of a HistoryStore (docs/database-design.md).

Privacy rules applied here, before anything is written:
    - store the verdict, not the content: no message text, OCR text, screenshots, QR payloads,
      Wi-Fi passwords or indicator evidence strings
    - links are reduced to their registrable domain plus a SHA-256 hash of the normalised URL
    - UPI codes keep only the payment provider part of the UPI ID ("@okaxis")
    - every scan expires after HISTORY_RETENTION_DAYS (default 90), enforced by the application so
      it works on the free Firebase Spark plan (Firestore TTL needs billing): expired scans are
      never returned, a user's expired scans are deleted when they sign in or open their history,
      and an admin can delete everyone's expired scans at once (purge_all_expired)
    - daily statistics are anonymous counters (no user ids)
A failure to write history or statistics never breaks the analysis itself.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Any

import click
from flask import current_app
from flask.cli import with_appcontext

from app.services.firebase_service import AuthUser
from app.services.history_store import HistoryStore, utcnow
from app.version import __version__

logger = logging.getLogger("qrguard.history")

SCHEMA_VERSION = 1
INPUT_KINDS = ("url", "message", "screenshot", "qr_camera", "qr_image")
REPORT_KINDS = ("false_positive", "false_negative", "scam")
REPORT_STATUSES = ("open", "reviewed")


def url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _url_target(analysis: dict[str, Any]) -> dict[str, Any]:
    url = analysis.get("normalized_url") or ""
    return {
        "kind": "url",
        "domain": analysis.get("domain") or analysis.get("host"),
        "url_hash": url_hash(url) if url else None,
    }


def build_target(response: dict[str, Any], kind: str) -> dict[str, Any]:
    analysis = response.get("analysis") or {}
    if kind == "url":
        return _url_target(analysis)
    qr = analysis.get("qr")
    if qr is not None:
        content_type = qr.get("content_type")
        if content_type in ("url", "dangerous") and analysis.get("normalized_url"):
            return _url_target(analysis)
        if content_type == "upi":
            vpa = (qr.get("parsed") or {}).get("payee_vpa") or ""
            return {"kind": "upi", "payee_domain": "@" + vpa.split("@")[-1] if "@" in vpa else None}
        return {"kind": content_type or "qr"}
    return {
        "kind": kind,
        "length": analysis.get("text_length"),
        "url_count": len(analysis.get("links") or []),
    }


def build_scan_record(response: dict[str, Any], kind: str, retention_days: int) -> dict[str, Any]:
    now = utcnow()
    return {
        "input_type": kind,
        "created_at": now,
        "expire_at": now + timedelta(days=retention_days),
        "risk_score": response["risk_score"],
        "risk_level": response["risk_level"],
        "confidence": response["confidence"],
        "verification": {
            "status": response["verification"]["status"],
            "source": response["verification"]["source"],
        },
        "categories": [c["id"] for c in response.get("categories", [])],
        # No "evidence" or "message": they can quote the user's content.
        "indicators": [
            {
                "id": i["id"],
                "title": i.get("title"),
                "severity": i.get("severity"),
                "score_contribution": i.get("score_contribution"),
                "source": i.get("source"),
            }
            for i in response.get("indicators", [])
        ],
        "recommended_action": response.get("recommendation"),
        "target": build_target(response, kind),
        "threat_intel": [
            {"provider": p["provider"], "status": p["status"]}
            for p in (response.get("threat_intel") or {}).get("providers", [])
        ],
        "engine_version": __version__,
        "schema_version": SCHEMA_VERSION,
    }


def public_scan(scan: dict[str, Any]) -> dict[str, Any]:
    """A stored scan as returned by GET /api/history."""
    out = {k: v for k, v in scan.items() if k not in ("expire_at", "schema_version")}
    for key in ("created_at",):
        if out.get(key) is not None and hasattr(out[key], "isoformat"):
            out[key] = out[key].isoformat()
    return out


def is_expired(scan: dict[str, Any], now: datetime | None = None) -> bool:
    expire_at = scan.get("expire_at")
    return expire_at is not None and expire_at <= (now or utcnow())


class HistoryService:
    def __init__(self, store: HistoryStore | None, retention_days: int = 90) -> None:
        self.store = store
        self.retention_days = retention_days

    @property
    def enabled(self) -> bool:
        return self.store is not None

    # ----- analysis hook ------------------------------------------------------------------------
    def record(
        self, user: AuthUser | None, response: dict[str, Any], kind: str, save_requested: bool
    ) -> dict[str, Any] | None:
        """Update anonymous statistics and, if asked and allowed, save the scan.

        Returns the "history" block for the response, or None when saving was not requested.
        """
        if self.store is None:
            return {"saved": False, "reason": "history_unavailable"} if save_requested else None
        ti_unavailable = any(
            p.get("status") == "unavailable"
            for p in (response.get("threat_intel") or {}).get("providers", [])
        )
        try:
            self.store.increment_stats(
                utcnow().date().isoformat(), kind, response["risk_level"], ti_unavailable
            )
        except Exception:  # noqa: BLE001 - statistics must never break an analysis
            logger.warning("stats update failed", extra={"event": "stats_error"})
        if not save_requested:
            return None
        if user is None:
            return {"saved": False, "reason": "sign_in_required"}
        try:
            if not self.save_history_enabled(user):
                return {"saved": False, "reason": "history_disabled"}
            scan_id = self.store.add_scan(
                user.uid, build_scan_record(response, kind, self.retention_days)
            )
        except Exception:  # noqa: BLE001 - the user still gets their result
            logger.warning("history write failed", extra={"event": "history_error"})
            return {"saved": False, "reason": "history_error"}
        return {"saved": True, "scan_id": scan_id}

    # ----- retention (application-level; no paid Firestore TTL) ---------------------------------
    def purge_expired(self, uid: str) -> int:
        """Delete one user's expired scans. Never raises: a failed purge must not block the user."""
        try:
            return self._store().delete_expired_scans(uid, utcnow())
        except Exception:  # noqa: BLE001 - expired scans stay hidden even if deletion fails
            logger.warning("expired-history purge failed", extra={"event": "history_purge_error"})
            return 0

    def purge_all_expired(self, limit: int = 5000) -> int:
        """Delete expired scans of every user (admin action / CLI), at most `limit` per call."""
        return self._store().delete_all_expired_scans(utcnow(), limit)

    def _store(self) -> HistoryStore:
        if self.store is None:  # routes check `enabled` first; this is a programming error
            raise RuntimeError("history store is not configured")
        return self.store

    # ----- user settings --------------------------------------------------------------------------
    def save_history_enabled(self, user: AuthUser) -> bool:
        store = self._store()
        settings = store.get_user(user.uid)
        return True if settings is None else bool(settings.get("save_history", True))

    def profile(self, user: AuthUser) -> dict[str, Any]:
        store = self._store()
        # The apps load the profile at every sign-in, which is when expired scans are cleaned up.
        self.purge_expired(user.uid)
        settings = store.get_user(user.uid)
        if settings is None:
            settings = {
                "created_at": utcnow(),
                "save_history": True,
                "is_anonymous": user.is_anonymous,
            }
            store.set_user(user.uid, settings)
        return {
            "uid": user.uid,
            "is_anonymous": user.is_anonymous,
            "admin": user.admin,
            "save_history": bool(settings.get("save_history", True)),
            "history_retention_days": self.retention_days,
        }

    def update_settings(self, user: AuthUser, save_history: bool) -> dict[str, Any]:
        store = self._store()
        self.profile(user)
        store.set_user(user.uid, {"save_history": save_history})
        return self.profile(user)

    # ----- reports ------------------------------------------------------------------------------
    def create_report(
        self, user: AuthUser, reported_as: str, note: str, scan_id: str | None
    ) -> str | None:
        """Returns the report id, or None if scan_id is not one of the user's scans."""
        store = self._store()
        target: dict[str, Any] = {}
        if scan_id is not None:
            scan = store.get_scan(user.uid, scan_id)
            if scan is None or is_expired(scan):
                return None
            target = scan.get("target") or {}
        return store.add_report(
            {
                "uid": user.uid,
                "scan_id": scan_id,
                "reported_as": reported_as,
                "domain": target.get("domain"),
                "url_hash": target.get("url_hash"),
                "note": note,
                "status": "open",
                "created_at": utcnow(),
            }
        )

    def delete_account_data(self, user: AuthUser) -> dict[str, int]:
        """ "Delete my data": all scans, then the uid on the user's reports."""
        store = self._store()
        deleted = store.delete_all_scans(user.uid)
        anonymised = store.anonymise_reports(user.uid)
        store.delete_user(user.uid)
        return {"deleted_scans": deleted, "anonymised_reports": anonymised}

    def stats(self, days: int) -> list[dict[str, Any]]:
        store = self._store()
        today = utcnow().date()
        dates = [(today - timedelta(days=offset)).isoformat() for offset in range(days)][::-1]
        return store.get_stats(dates)


@click.command("purge-expired-history")
@with_appcontext
def purge_expired_command() -> None:
    """`flask --app wsgi purge-expired-history`: delete every user's expired scans now."""
    history = current_app.extensions["qrguard.history"]
    if not history.enabled:
        raise click.ClickException("History is not configured (set FIREBASE_PROJECT_ID)")
    total = 0
    while True:  # purge_all_expired works in chunks; repeat until nothing is left
        deleted = history.purge_all_expired()
        total += deleted
        if deleted == 0:
            break
    click.echo(f"Deleted {total} expired scan(s).")
