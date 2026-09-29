"""Request/response middleware: request IDs, size checks, access logging, security headers."""

from __future__ import annotations

import logging
import re
import time
import uuid

from flask import Flask, Response, current_app, g, request

from app.errors import APIError

logger = logging.getLogger("qrguard.access")

# A client may send its own X-Request-ID (useful when debugging from Postman or the apps).
# We only accept short, safe values so the header cannot be used for log injection.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9\-]{8,64}$")

# This API only ever returns JSON, so the strictest browser policies are safe.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-site",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    # Analysis results are personal; browsers and proxies must not cache them.
    "Cache-Control": "no-store",
}


def register_middleware(app: Flask) -> None:
    @app.before_request
    def assign_request_id() -> None:
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex[:16]
        g.start_time = time.perf_counter()

    @app.before_request
    def limit_json_body_size() -> None:
        # MAX_CONTENT_LENGTH already caps every body (uploads included).
        # JSON bodies get a much smaller limit because they only carry text.
        config = current_app.config["QRGUARD"]
        if request.is_json and (request.content_length or 0) > config.max_json_bytes:
            raise APIError(
                413,
                "PAYLOAD_TOO_LARGE",
                f"JSON body must be {config.max_json_kb} KB or smaller.",
            )

    @app.after_request
    def add_headers_and_log(response: Response) -> Response:
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if current_app.config["QRGUARD"].is_production:
            # Only meaningful over HTTPS, which Render (and similar platforms) provide.
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        duration_ms = round((time.perf_counter() - g.get("start_time", time.perf_counter())) * 1000)
        # request.path excludes the query string, so user input in ?url=... is never logged.
        logger.info(
            "request completed",
            extra={
                "event": "http_request",
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response
