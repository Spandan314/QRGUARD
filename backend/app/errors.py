"""Consistent JSON error responses.

Every error the API returns has the same shape::

    {"error": {"code": "VALIDATION_ERROR", "message": "...", "request_id": "..."}}

Clients can rely on ``code`` (stable, machine-readable) and show ``message``
(human-readable). Stack traces are written to the server log only, never sent to
the client.
"""

from __future__ import annotations

import logging
from typing import Any

from flask import Flask, Response, g, jsonify
from werkzeug.exceptions import HTTPException

logger = logging.getLogger("qrguard.errors")

# Default error code for each HTTP status raised by Flask / Werkzeug / Flask-Limiter.
HTTP_STATUS_CODES: dict[int, str] = {
    400: "BAD_REQUEST",
    401: "AUTH_REQUIRED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    405: "METHOD_NOT_ALLOWED",
    413: "PAYLOAD_TOO_LARGE",
    415: "UNSUPPORTED_MEDIA_TYPE",
    422: "UNPROCESSABLE_ENTITY",
    429: "RATE_LIMITED",
    500: "INTERNAL_ERROR",
    501: "NOT_IMPLEMENTED",
    503: "SERVICE_UNAVAILABLE",
}

# Friendly messages that do not leak implementation details.
HTTP_STATUS_MESSAGES: dict[int, str] = {
    400: "The request could not be understood.",
    401: "Authentication is required.",
    403: "You do not have permission to perform this action.",
    404: "The requested resource was not found.",
    405: "This HTTP method is not allowed for this endpoint.",
    413: "The request body is too large.",
    415: "Unsupported content type.",
    429: "Too many requests. Please wait and try again.",
    500: "An unexpected error occurred. Please try again later.",
    501: "This feature is not implemented yet.",
    503: "The service is temporarily unavailable.",
}


class APIError(Exception):
    """Raise this anywhere in a request to return a structured JSON error.

    Example::

        raise APIError(400, "INVALID_URL", "Please enter a valid http(s) link.")
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def error_response(
    status: int, code: str, message: str, details: list[dict[str, Any]] | None = None
) -> tuple[Response, int]:
    body: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": getattr(g, "request_id", None),
    }
    if details:
        body["details"] = details
    return jsonify({"error": body}), status


def register_error_handlers(app: Flask) -> None:
    @app.errorhandler(APIError)
    def handle_api_error(err: APIError):
        return error_response(err.status, err.code, err.message, err.details)

    @app.errorhandler(HTTPException)
    def handle_http_exception(err: HTTPException):
        status = err.code or 500
        code = HTTP_STATUS_CODES.get(status, "HTTP_ERROR")
        message = HTTP_STATUS_MESSAGES.get(status, "The request failed.")
        response, status = error_response(status, code, message)
        # Keep headers such as Allow (405) or Retry-After (429) from the original exception.
        for header, value in err.get_headers():
            if header.lower() != "content-type":
                response.headers[header] = value
        return response, status

    @app.errorhandler(Exception)
    def handle_unexpected_error(err: Exception):
        # Full traceback goes to the server log; the client only gets a generic message.
        logger.exception("Unhandled exception: %s", type(err).__name__)
        return error_response(500, "INTERNAL_ERROR", HTTP_STATUS_MESSAGES[500])
