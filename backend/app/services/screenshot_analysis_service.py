"""Screenshot pipeline: validate image -> OCR -> the EXISTING message pipeline.

Nothing here detects scams by itself. The text read from the screenshot goes through the same
scam-message rules, link extraction, URL analyzer (with its SSRF protection) and scoring engine
as POST /api/analyze/message. OCR only adds informational indicators (weight 0) that explain
reading problems and lower the confidence.

Privacy: the image is processed in memory and never written to disk; neither the image nor the
extracted text is logged or stored. The extracted text is returned to the caller only.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.ocr import OcrEngine
from app.scoring.indicator import Indicator
from app.services.message_analysis_service import MessageAnalysisService, TextNotAnalyzableError
from app.utils.image_validation import validate_image

MAX_TEXT_CHARS = 5000  # same limit as a pasted message


class NoTextFoundError(ValueError):
    """OCR found no readable text in the image."""


class ScreenshotAnalysisService:
    def __init__(
        self,
        message_service: MessageAnalysisService,
        ocr_engine: OcrEngine,
        max_bytes: int,
        max_pixels: int,
    ) -> None:
        self.message_service = message_service
        self.ocr_engine = ocr_engine  # attribute so tests can swap in a fake engine
        self.max_bytes = max_bytes
        self.max_pixels = max_pixels

    def analyze(self, data: bytes) -> dict[str, Any]:
        image = validate_image(data, self.max_bytes, self.max_pixels)
        try:
            ocr = self.ocr_engine.extract(image.image)  # OcrError subclasses propagate to the route
        finally:
            image.image.close()

        text = ocr.text.strip()
        if not text:
            raise NoTextFoundError("No readable text was found in the image.")

        indicators: list[Indicator] = []
        low_reasons: list[str] = []
        truncated = len(text) > MAX_TEXT_CHARS
        if truncated:
            text = text[:MAX_TEXT_CHARS]
            indicators.append(Indicator("OCR_TEXT_TRUNCATED", f"first {MAX_TEXT_CHARS} characters"))
        if ocr.quality == "poor":
            indicators.append(
                Indicator("OCR_LOW_CONFIDENCE", f"average OCR confidence {ocr.mean_confidence}%")
            )
            low_reasons.append("screenshot text was hard to read")

        ocr_block = {
            "ocr": {
                "engine": ocr.engine,
                "extracted_text": text,  # returned to the caller only; never logged or stored
                "confidence": ocr.mean_confidence,
                "quality": ocr.quality,
                "word_count": ocr.word_count,
                "truncated": truncated,
            },
            "image": image.describe(),
        }
        try:
            return self.message_service.analyze_text(
                text,
                input_type="screenshot",
                extra_indicators=indicators,
                extra_low_confidence_reasons=low_reasons,
                extra_analysis=ocr_block,
            )
        except TextNotAnalyzableError as exc:
            raise NoTextFoundError("No readable text was found in the image.") from exc
