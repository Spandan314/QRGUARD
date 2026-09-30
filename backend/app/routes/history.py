"""/api/history: the signed-in user's saved scans (verdicts only, never the checked content)."""

from __future__ import annotations

import re

from flask import Blueprint, current_app, jsonify, request

from app.errors import APIError
from app.schemas import SCAN_ID_PATTERN
from app.services.auth import require_auth, signed_in_user
from app.services.history_service import public_scan
from app.services.history_store import InvalidCursorError

history_bp = Blueprint("history", __name__)


def _store():
    return current_app.extensions["qrguard.history"].store


def _scan_id(value: str) -> str:
    if not re.fullmatch(SCAN_ID_PATTERN, value):
        raise APIError(404, "NOT_FOUND", "This scan does not exist.")
    return value


@history_bp.get("/history")
@require_auth
def list_history():
    try:
        limit = int(request.args.get("limit", "20"))
    except ValueError:
        limit = -1
    if not 1 <= limit <= 50:
        raise APIError(400, "VALIDATION_ERROR", "limit must be a number from 1 to 50.")
    cursor = request.args.get("cursor") or None
    if cursor is not None and not re.fullmatch(SCAN_ID_PATTERN, cursor):
        raise APIError(400, "VALIDATION_ERROR", "Invalid cursor.")
    try:
        items, next_cursor = _store().list_scans(signed_in_user().uid, limit, cursor)
    except InvalidCursorError as exc:
        raise APIError(400, "VALIDATION_ERROR", "Invalid cursor.") from exc
    return jsonify({"items": [public_scan(item) for item in items], "next_cursor": next_cursor})


@history_bp.get("/history/<string:scan_id>")
@require_auth
def get_history_item(scan_id: str):
    scan = _store().get_scan(signed_in_user().uid, _scan_id(scan_id))
    if scan is None:
        raise APIError(404, "NOT_FOUND", "This scan does not exist.")
    return jsonify(public_scan(scan))


@history_bp.delete("/history/<string:scan_id>")
@require_auth
def delete_history_item(scan_id: str):
    # A scan id belonging to another user is simply "not found" in the caller's own collection.
    if not _store().delete_scan(signed_in_user().uid, _scan_id(scan_id)):
        raise APIError(404, "NOT_FOUND", "This scan does not exist.")
    return "", 204


@history_bp.delete("/history")
@require_auth
def delete_all_history():
    return jsonify({"deleted": _store().delete_all_scans(signed_in_user().uid)})
