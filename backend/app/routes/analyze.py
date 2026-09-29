"""POST /api/analyze/*: analysis endpoints.

``/analyze/url`` and ``/analyze/message`` are implemented. The other endpoints validate
requests against the API contract and answer 501 NOT_IMPLEMENTED until their analyzers are
built, so the web and mobile teams can already use the real request/response/error shapes.

Privacy: submitted text is never logged (the access log records only method, path, status).
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from app.analyzers.url_normalizer import URLValidationError
from app.errors import APIError
from app.extensions import analyze_rate_limit, limiter
from app.schemas import AnalyzeMessageRequest, AnalyzeQrContentRequest, AnalyzeUrlRequest
from app.services.message_analysis_service import TextNotAnalyzableError
from app.utils.validation import parse_json_body, require_multipart_file
from app.version import __version__

analyze_bp = Blueprint("analyze", __name__)


def _not_implemented(module: str, planned: str) -> APIError:
    return APIError(
        501,
        "NOT_IMPLEMENTED",
        f"{module} is not implemented yet (planned: {planned}). Your request was valid.",
    )


@analyze_bp.post("/analyze/url")
@limiter.limit(analyze_rate_limit)
def analyze_url():
    body = parse_json_body(AnalyzeUrlRequest)
    service = current_app.extensions["qrguard.url_analysis"]
    try:
        result = service.analyze(body.url)
    except URLValidationError as exc:
        raise APIError(400, exc.code, exc.message) from exc
    # save_to_history is accepted now and used once history is implemented (Firebase phase).
    return jsonify({"request_id": g.request_id, **result, "engine_version": __version__})


@analyze_bp.post("/analyze/message")
@limiter.limit(analyze_rate_limit)
def analyze_message():
    body = parse_json_body(AnalyzeMessageRequest)
    service = current_app.extensions["qrguard.message_analysis"]
    try:
        result = service.analyze(body.text)
    except TextNotAnalyzableError as exc:
        raise APIError(422, "TEXT_NOT_ANALYZABLE", str(exc)) from exc
    return jsonify({"request_id": g.request_id, **result, "engine_version": __version__})


@analyze_bp.post("/analyze/screenshot")
@limiter.limit(analyze_rate_limit)
def analyze_screenshot():
    require_multipart_file("file")
    raise _not_implemented("Screenshot analysis", "OCR / screenshot phase")


@analyze_bp.post("/analyze/qr")
@limiter.limit(analyze_rate_limit)
def analyze_qr():
    # Two accepted forms: JSON {"content": ...} (camera) or multipart image upload.
    if request.mimetype == "multipart/form-data":
        require_multipart_file("file")
    else:
        parse_json_body(AnalyzeQrContentRequest)
    raise _not_implemented("QR analysis", "QR analysis phase")
