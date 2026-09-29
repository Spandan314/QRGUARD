"""/api/admin/*: small admin dashboard API (custom claim admin=true, checked on the server).

Only anonymous aggregates and user reports are exposed: no user's scan history.
"""

from __future__ import annotations

import re

from flask import Blueprint, current_app, jsonify, request

from app.errors import APIError
from app.schemas import SCAN_ID_PATTERN, UpdateReportRequest
from app.services.auth import require_admin
from app.utils.validation import parse_json_body

admin_bp = Blueprint("admin", __name__)


def _history():
    return current_app.extensions["qrguard.history"]


def _iso(row: dict) -> dict:
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in row.items()}


@admin_bp.get("/admin/stats")
@require_admin
def stats():
    try:
        days = int(request.args.get("days", "30"))
    except ValueError:
        days = -1
    if not 1 <= days <= 90:
        raise APIError(400, "VALIDATION_ERROR", "days must be a number from 1 to 90.")
    threat_intel = current_app.extensions["qrguard.url_analysis"].threat_intel.status()
    return jsonify({"days": _history().stats(days), "threat_intel": threat_intel})


@admin_bp.get("/admin/reports")
@require_admin
def list_reports():
    status = request.args.get("status", "open")
    if status not in ("open", "reviewed"):
        raise APIError(400, "VALIDATION_ERROR", "status must be 'open' or 'reviewed'.")
    reports = _history().store.list_reports(status, 100)
    # The reporter's uid is not shown to admins.
    return jsonify({"items": [_iso({k: v for k, v in r.items() if k != "uid"}) for r in reports]})


@admin_bp.patch("/admin/reports/<string:report_id>")
@require_admin
def update_report(report_id: str):
    body = parse_json_body(UpdateReportRequest)
    if not re.fullmatch(SCAN_ID_PATTERN, report_id) or not _history().store.update_report(
        report_id, body.status
    ):
        raise APIError(404, "NOT_FOUND", "This report does not exist.")
    return jsonify({"id": report_id, "status": body.status})
