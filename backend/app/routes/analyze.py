"""POST /api/analyze/*: analysis endpoints.

``/analyze/url``, ``/analyze/message`` and ``/analyze/screenshot`` are implemented.
``/analyze/qr`` validates requests against the API contract and answers 501 NOT_IMPLEMENTED
until its analyzer is built, so the web and mobile teams can already use the real shapes.

Privacy: submitted text and images are never logged (the access log records only method,
path, status and duration) and never stored.
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from app.analyzers.ocr import OcrBusyError, OcrError, OcrUnavailableError
from app.analyzers.url_normalizer import URLValidationError
from app.errors import APIError
from app.extensions import analyze_rate_limit, limiter, screenshot_rate_limit
from app.schemas import AnalyzeMessageRequest, AnalyzeQrContentRequest, AnalyzeUrlRequest
from app.services.message_analysis_service import TextNotAnalyzableError
from app.services.screenshot_analysis_service import NoTextFoundError
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


def _read_upload(field_name: str = "file") -> bytes:
    """Return the uploaded file's bytes (never its name, which is not trusted or used)."""
    require_multipart_file(field_name)
    if len(request.files.getlist(field_name)) != 1:
        raise APIError(
            400, "VALIDATION_ERROR", f"Send exactly one file in the '{field_name}' field."
        )
    save = request.form.get("save_to_history", "false").strip().lower()
    if save not in ("true", "false"):
        raise APIError(400, "VALIDATION_ERROR", "save_to_history must be 'true' or 'false'.")
    limit = current_app.config["QRGUARD"].max_content_length
    return request.files[field_name].stream.read(limit + 1)


@analyze_bp.post("/analyze/screenshot")
@limiter.limit(analyze_rate_limit)
@limiter.limit(screenshot_rate_limit)
def analyze_screenshot():
    data = _read_upload("file")
    service = current_app.extensions["qrguard.screenshot_analysis"]
    try:
        result = service.analyze(data)
    except NoTextFoundError as exc:
        raise APIError(422, "NO_TEXT_FOUND", str(exc)) from exc
    except OcrUnavailableError as exc:
        raise APIError(
            503, "OCR_UNAVAILABLE", "Screenshot analysis is temporarily unavailable."
        ) from exc
    except OcrBusyError as exc:
        raise APIError(503, "OCR_BUSY", "The server is busy. Please try again shortly.") from exc
    except OcrError as exc:
        raise APIError(422, "OCR_FAILED", "The text in this image could not be read.") from exc
    # save_to_history is validated now and used once history is implemented (Firebase phase).
    return jsonify({"request_id": g.request_id, **result, "engine_version": __version__})


@analyze_bp.post("/analyze/qr")
@limiter.limit(analyze_rate_limit)
def analyze_qr():
    # Two accepted forms: JSON {"content": ...} (camera) or multipart image upload.
    if request.mimetype == "multipart/form-data":
        require_multipart_file("file")
    else:
        parse_json_body(AnalyzeQrContentRequest)
    raise _not_implemented("QR analysis", "QR analysis phase")
