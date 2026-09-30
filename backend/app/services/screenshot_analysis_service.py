"""Screenshot pipeline: validate image -> QR decode + OCR -> the EXISTING message pipeline.

Nothing here detects scams by itself. The text read from the screenshot goes through the same
scam-message rules, link extraction, URL analyzer (with its SSRF protection) and scoring engine
as POST /api/analyze/message. OCR only adds informational indicators (weight 0) that explain
reading problems and lower the confidence.

QR codes visible in the screenshot are decoded too: links in them are analysed like links in
the text (``found_in: "qr"``), and a UPI payment QR adds its QR evidence (plus the
"scan to receive money" rule when the text promises money). A screenshot with only a QR code
and no text is analysed like POST /api/analyze/qr.

Privacy: the image is processed in memory and never written to disk; neither the image nor the
extracted text is logged or stored. The extracted text is returned to the caller only.
"""

from __future__ import annotations

from typing import Any

from app.analyzers.ocr import OcrEngine
from app.analyzers.qr_decoder import decode_qr_codes
from app.analyzers.qr_payload import classify, payload_indicators
from app.scoring.indicator import Indicator
from app.services.message_analysis_service import MessageAnalysisService, TextNotAnalyzableError
from app.services.qr_analysis_service import QrAnalysisService, safe_display
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
        qr_service: QrAnalysisService | None = None,
    ) -> None:
        self.message_service = message_service
        self.qr_service = qr_service
        self.ocr_engine = ocr_engine  # attribute so tests can swap in a fake engine
        self.max_bytes = max_bytes
        self.max_pixels = max_pixels

    def analyze(self, data: bytes) -> dict[str, Any]:
        image = validate_image(data, self.max_bytes, self.max_pixels)
        try:
            qr_codes = decode_qr_codes(image.image) if self.qr_service else []
            ocr = self.ocr_engine.extract(image.image)  # OcrError subclasses propagate to the route
        finally:
            image.image.close()

        text = ocr.text.strip()
        if not text and qr_codes:
            return self._qr_only(qr_codes, ocr, image.describe())
        if not text:
            raise NoTextFoundError("No readable text or QR code was found in the image.")

        rules = self.message_service.url_service.rules
        qr_links: list[str] = []
        upi_indicators: list[Indicator] = []
        qr_rows = []
        for code in qr_codes:
            payload = classify(code, rules.dangerous_schemes)
            if payload.content_type in ("url", "dangerous"):
                qr_links.append(payload.raw)
                used_as = "link"
            elif payload.content_type == "upi" and not upi_indicators:
                upi_indicators = payload_indicators(payload, rules)
                used_as = "upi_payment"
            else:
                used_as = "listed_only"
            qr_rows.append(
                {
                    "content_type": payload.content_type,
                    "decoded_content": safe_display(payload),
                    "used_as": used_as,
                }
            )

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
            "qr_codes": qr_rows,
        }
        try:
            return self.message_service.analyze_text(
                text,
                input_type="screenshot",
                extra_indicators=indicators,
                extra_low_confidence_reasons=low_reasons,
                extra_analysis=ocr_block,
                extra_links=qr_links,
                upi_qr_indicators=upi_indicators,
            )
        except TextNotAnalyzableError as exc:
            if qr_codes:
                return self._qr_only(qr_codes, ocr, image.describe())
            raise NoTextFoundError("No readable text was found in the image.") from exc

    def _qr_only(self, codes: list[str], ocr, image: dict[str, Any]) -> dict[str, Any]:
        """No usable text, but QR code(s): analyse them exactly like /api/analyze/qr."""
        response = self.qr_service.analyze_payloads(
            codes, source="screenshot", image=image, input_type="screenshot"
        )
        response["analysis"]["ocr"] = {
            "engine": ocr.engine,
            "extracted_text": ocr.text.strip(),
            "confidence": ocr.mean_confidence,
            "quality": ocr.quality,
            "word_count": ocr.word_count,
            "truncated": False,
        }
        return response
