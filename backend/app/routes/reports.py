"""POST /api/reports: users tell us about a wrong result (false positive / negative) or a scam."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from app.errors import APIError
from app.extensions import limiter, reports_rate_limit
from app.schemas import CreateReportRequest
from app.services.auth import require_auth, signed_in_user
from app.utils.validation import parse_json_body

reports_bp = Blueprint("reports", __name__)


@reports_bp.post("/reports")
@limiter.limit(reports_rate_limit)
@require_auth
def create_report():
    body = parse_json_body(CreateReportRequest)
    report_id = current_app.extensions["qrguard.history"].create_report(
        signed_in_user(), body.reported_as, body.note, body.scan_id
    )
    if report_id is None:
        raise APIError(404, "NOT_FOUND", "This scan does not exist.")
    return jsonify({"id": report_id}), 201
