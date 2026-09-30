"""Request schemas (the API contract from docs/api-spec.md, written as Pydantic models).

``extra="forbid"`` rejects unknown fields, which catches client typos early
(e.g. ``"URL"`` instead of ``"url"``) and keeps the contract strict.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class AnalyzeUrlRequest(_Request):
    url: StrictStr = Field(min_length=1, max_length=2048)
    save_to_history: StrictBool = False


class AnalyzeMessageRequest(_Request):
    text: StrictStr = Field(min_length=1, max_length=5000)
    save_to_history: StrictBool = False


class AnalyzeQrContentRequest(_Request):
    """QR already decoded on the device (camera scan)."""

    content: StrictStr = Field(min_length=1, max_length=4096)
    source: Literal["camera"] = "camera"
    save_to_history: StrictBool = False


SCAN_ID_PATTERN = r"^[A-Za-z0-9_-]{8,64}$"


class UpdateSettingsRequest(_Request):
    save_history: StrictBool


class CreateReportRequest(_Request):
    reported_as: Literal["false_positive", "false_negative", "scam"]
    # Users are warned not to include personal data; the note is shown to admins only.
    note: StrictStr = Field(default="", max_length=280)
    scan_id: StrictStr | None = Field(default=None, pattern=SCAN_ID_PATTERN)


class UpdateReportRequest(_Request):
    status: Literal["open", "reviewed"]


class GenerateQrRequest(_Request):
    type: Literal["text", "url", "wifi", "email", "phone"]
    data: dict[StrictStr, StrictStr] = Field(min_length=1, max_length=10)
    format: Literal["png", "svg"] = "png"
    size: int = Field(default=512, ge=128, le=1024)
