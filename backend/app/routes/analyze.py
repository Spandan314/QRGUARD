"""POST /api/analyze/*: analysis endpoints.

PHASE 2 FOUNDATION: requests are fully validated against the API contract, then
the endpoint answers 501 NOT_IMPLEMENTED. This lets the web and mobile teams (and
Postman) test the real request/response/error shapes before each analyzer exists.
Each stub is replaced by its analyzer in the following steps.
"""

from __future__ import annotations

from flask import Blueprint, request

from app.errors import APIError
from app.extensions import analyze_rate_limit, limiter
from app.schemas import AnalyzeMessageRequest, AnalyzeQrContentRequest, AnalyzeUrlRequest
from app.utils.validation import parse_json_body, require_multipart_file

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
    parse_json_body(AnalyzeUrlRequest)
    raise _not_implemented("URL analysis", "Phase 2: URL analysis + risk engine")


@analyze_bp.post("/analyze/message")
@limiter.limit(analyze_rate_limit)
def analyze_message():
    parse_json_body(AnalyzeMessageRequest)
    raise _not_implemented("Scam message analysis", "Phase 3")


@analyze_bp.post("/analyze/screenshot")
@limiter.limit(analyze_rate_limit)
def analyze_screenshot():
    require_multipart_file("file")
    raise _not_implemented("Screenshot analysis", "Phase 3")


@analyze_bp.post("/analyze/qr")
@limiter.limit(analyze_rate_limit)
def analyze_qr():
    # Two accepted forms: JSON {"content": ...} (camera) or multipart image upload.
    if request.mimetype == "multipart/form-data":
        require_multipart_file("file")
    else:
        parse_json_body(AnalyzeQrContentRequest)
    raise _not_implemented("QR analysis", "Phase 2: URL analysis + risk engine")
