"""POST /api/generate/qr: QR generator utility (separate from security analysis).

The web and mobile apps generate QR codes locally, so private data such as
Wi-Fi passwords never leaves the device. This endpoint exists for API
completeness and Postman testing. Payloads are never logged or stored.
"""

from __future__ import annotations

from flask import Blueprint

from app.errors import APIError
from app.extensions import limiter
from app.schemas import GenerateQrRequest
from app.utils.validation import parse_json_body

generate_bp = Blueprint("generate", __name__)


@generate_bp.post("/generate/qr")
@limiter.limit("30 per minute")
def generate_qr():
    parse_json_body(GenerateQrRequest)
    raise APIError(
        501,
        "NOT_IMPLEMENTED",
        "QR generation endpoint is not implemented yet. Your request was valid.",
    )
