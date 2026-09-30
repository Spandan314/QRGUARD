"""POST /api/generate/qr: QR generator utility (separate from security analysis).

The web and mobile apps can generate QR codes locally, so private data such as Wi-Fi
passwords need not leave the device. This endpoint builds the same payloads server-side
(PNG as base64, or SVG). Payloads are never logged or stored; Wi-Fi passwords are masked
in the response (they are only inside the image).
"""

from __future__ import annotations

from flask import Blueprint, current_app, g, jsonify

from app.extensions import limiter
from app.schemas import GenerateQrRequest
from app.services.qr_generator import generate
from app.utils.validation import parse_json_body

generate_bp = Blueprint("generate", __name__)


@generate_bp.post("/generate/qr")
@limiter.limit("30 per minute")
def generate_qr():
    body = parse_json_body(GenerateQrRequest)
    url_rules = current_app.extensions["qrguard.url_analysis"].rules
    result = generate(body.type, body.data, body.format, body.size, url_rules)
    return jsonify({"request_id": g.request_id, **result})
