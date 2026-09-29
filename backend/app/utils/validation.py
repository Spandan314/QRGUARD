"""Helpers that turn raw requests into validated schema objects, or raise APIError."""

from __future__ import annotations

from typing import TypeVar

from flask import request
from pydantic import BaseModel, ValidationError

from app.errors import APIError

ModelT = TypeVar("ModelT", bound=BaseModel)


def parse_json_body(model: type[ModelT]) -> ModelT:
    """Validate the JSON request body against ``model``.

    Returns the model instance or raises:
      * 415 UNSUPPORTED_MEDIA_TYPE if Content-Type is not application/json
      * 400 INVALID_JSON           if the body is not a JSON object
      * 400 VALIDATION_ERROR       if fields are missing / wrong type / too long
    """
    if not request.is_json:
        raise APIError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.")

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise APIError(400, "INVALID_JSON", "Request body must be a valid JSON object.")

    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise APIError(
            400,
            "VALIDATION_ERROR",
            "Some fields are missing or invalid.",
            details=validation_details(exc),
        ) from exc


def validation_details(exc: ValidationError) -> list[dict[str, str]]:
    """Field-level errors WITHOUT echoing the submitted values back (privacy)."""
    return [
        {"field": ".".join(str(part) for part in err["loc"]) or "body", "message": err["msg"]}
        for err in exc.errors(include_input=False, include_url=False)
    ]


def require_multipart_file(field_name: str = "file") -> None:
    """Ensure the request is multipart/form-data with a non-empty file field.

    Detailed image validation (type, magic bytes, dimensions) is added with the
    OCR / QR image modules.
    """
    if request.mimetype != "multipart/form-data":
        raise APIError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be multipart/form-data.")
    uploaded = request.files.get(field_name)
    if uploaded is None or not uploaded.filename:
        raise APIError(400, "MISSING_FILE", f"Attach an image in the '{field_name}' field.")
