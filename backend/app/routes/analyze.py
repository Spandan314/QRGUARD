"""POST /api/analyze/*: analysis endpoints.

All four analysis endpoints are implemented: ``/analyze/url``, ``/analyze/message``,
``/analyze/screenshot`` (OCR) and ``/analyze/qr`` (decoded content or a QR image).

Privacy: submitted text and images are never logged (the access log records only method,
path, status and duration) and never stored. With `save_to_history: true` and a signed-in user,
only the privacy-minimised verdict is saved (app/services/history_service.py).
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify, request

from app.analyzers.ocr import OcrBusyError, OcrError, OcrUnavailableError
from app.analyzers.url_normalizer import URLValidationError
from app.errors import APIError
from app.extensions import analyze_rate_limit, limiter, screenshot_rate_limit
from app.schemas import AnalyzeMessageRequest, AnalyzeQrContentRequest, AnalyzeUrlRequest
from app.services.auth import current_user, optional_auth
from app.services.message_analysis_service import TextNotAnalyzableError
from app.services.qr_analysis_service import NoQrFoundError
from app.services.screenshot_analysis_service import NoTextFoundError
from app.utils.validation import parse_json_body, require_multipart_file
from app.version import __version__

analyze_bp = Blueprint("analyze", __name__)


def _respond(result: dict, kind: str, save_to_history: bool):
    """Common response: request id + result + engine version (+ history outcome if asked)."""
    history = current_app.extensions["qrguard.history"].record(
        current_user(), result, kind, save_to_history
    )
    body = {"request_id": g.request_id, **result, "engine_version": __version__}
    if history is not None:
        body["history"] = history
    return jsonify(body)


@analyze_bp.post("/analyze/url")
@limiter.limit(analyze_rate_limit)
@optional_auth
def analyze_url():
    body = parse_json_body(AnalyzeUrlRequest)
    service = current_app.extensions["qrguard.url_analysis"]
    try:
        result = service.analyze(body.url)
    except URLValidationError as exc:
        raise APIError(400, exc.code, exc.message) from exc
    return _respond(result, "url", body.save_to_history)


@analyze_bp.post("/analyze/message")
@limiter.limit(analyze_rate_limit)
@optional_auth
def analyze_message():
    body = parse_json_body(AnalyzeMessageRequest)
    service = current_app.extensions["qrguard.message_analysis"]
    try:
        result = service.analyze(body.text)
    except TextNotAnalyzableError as exc:
        raise APIError(422, "TEXT_NOT_ANALYZABLE", str(exc)) from exc
    return _respond(result, "message", body.save_to_history)


def _read_upload(field_name: str = "file") -> tuple[bytes, bool]:
    """The uploaded file's bytes (never its name, which is not trusted) and save_to_history."""
    require_multipart_file(field_name)
    if len(request.files.getlist(field_name)) != 1:
        raise APIError(
            400, "VALIDATION_ERROR", f"Send exactly one file in the '{field_name}' field."
        )
    save = request.form.get("save_to_history", "false").strip().lower()
    if save not in ("true", "false"):
        raise APIError(400, "VALIDATION_ERROR", "save_to_history must be 'true' or 'false'.")
    limit = current_app.config["QRGUARD"].max_content_length
    return request.files[field_name].stream.read(limit + 1), save == "true"


@analyze_bp.post("/analyze/screenshot")
@limiter.limit(analyze_rate_limit)
@limiter.limit(screenshot_rate_limit)
@optional_auth
def analyze_screenshot():
    data, save = _read_upload("file")
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
    return _respond(result, "screenshot", save)


@analyze_bp.post("/analyze/qr")
@limiter.limit(analyze_rate_limit)
@optional_auth
def analyze_qr():
    # Two accepted forms: JSON {"content": ...} (camera) or multipart image upload.
    service = current_app.extensions["qrguard.qr_analysis"]
    if request.mimetype == "multipart/form-data":
        data, save = _read_upload("file")
        try:
            result = service.analyze_image(data)
        except NoQrFoundError as exc:
            raise APIError(422, "NO_QR_FOUND", str(exc)) from exc
        return _respond(result, "qr_image", save)
    body = parse_json_body(AnalyzeQrContentRequest)
    result = service.analyze_content(body.content, source=body.source)
    return _respond(result, "qr_camera", body.save_to_history)
