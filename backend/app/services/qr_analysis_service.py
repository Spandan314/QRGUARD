"""QR pipeline: decode (image) or accept decoded content (camera) -> classify -> reuse analyzers.

    web links / javascript: / intent:  -> the existing URL analyzer (SSRF-safe, same scoring)
    text, vCard, SMS or e-mail body   -> the existing scam-message pipeline
    UPI, Wi-Fi, phone, geo, app links  -> QR payload indicators, scored by the same engine

Several QR codes in one image: each is analysed and the riskiest one decides the result (the
others are listed). Nothing in a QR code is ever opened, dialled, paid or connected to; the
URL analyzer may only check where a shortened link redirects (SSRF-protected, no page content).
Privacy: decoded content is never logged or stored; Wi-Fi passwords are never returned.
"""

from __future__ import annotations

import re
from typing import Any

from app.analyzers.qr_decoder import decode_qr_codes
from app.analyzers.qr_payload import QrPayload, classify, payload_indicators
from app.analyzers.url_normalizer import URLValidationError
from app.scoring.engine import ScoringContext, score_indicators
from app.scoring.recommendations import DISCLAIMER, recommendation_for, summary_for
from app.services.message_analysis_service import MessageAnalysisService, TextNotAnalyzableError
from app.services.url_analysis_service import UrlAnalysisService
from app.utils.image_validation import validate_image

UNVERIFIED_QR_TEXT = (
    "There is insufficient evidence to establish trust. A SAFE result does not guarantee that "
    "the QR code is safe."
)
_WIFI_PASSWORD_RE = re.compile(r"(?i)(\bP:)((?:\\.|[^;])*)")


class NoQrFoundError(ValueError):
    """No QR code could be decoded from the image."""


def safe_display(payload: QrPayload) -> str:
    """The decoded content as shown to the user: Wi-Fi passwords are masked."""
    if payload.content_type == "wifi":
        return _WIFI_PASSWORD_RE.sub(
            lambda m: m.group(1) + ("***" if m.group(2) else ""), payload.raw
        )
    return payload.raw


class QrAnalysisService:
    def __init__(
        self,
        url_service: UrlAnalysisService,
        message_service: MessageAnalysisService,
        max_bytes: int,
        max_pixels: int,
    ) -> None:
        self.url_service = url_service
        self.message_service = message_service
        self.max_bytes = max_bytes
        self.max_pixels = max_pixels

    # ----- entry points ----------------------------------------------------------------------
    def analyze_content(self, content: str, source: str = "camera") -> dict[str, Any]:
        """Content already decoded on the device (camera scan)."""
        return self.analyze_payloads([content], source=source)

    def analyze_image(self, data: bytes) -> dict[str, Any]:
        image = validate_image(data, self.max_bytes, self.max_pixels)
        try:
            codes = decode_qr_codes(image.image)
        finally:
            image.image.close()
        if not codes:
            raise NoQrFoundError("No QR code could be read from this image.")
        return self.analyze_payloads(codes, source="image", image=image.describe())

    def analyze_payloads(
        self,
        contents: list[str],
        source: str,
        image: dict[str, Any] | None = None,
        input_type: str = "qr",
    ) -> dict[str, Any]:
        results = [self._analyze_one(content, input_type) for content in contents]
        chosen = max(range(len(results)), key=lambda i: results[i][0]["risk_score"])
        response, payload = results[chosen]
        response["analysis"] = {
            "qr": {
                "source": source,
                "codes_found": len(results),
                "decoded_content": safe_display(payload),
                **payload.public(),
            },
            **({"image": image} if image else {}),
            **({"qr_codes": self._summaries(results, chosen)} if len(results) > 1 else {}),
            **response.get("analysis", {}),
        }
        return response

    # ----- one payload -----------------------------------------------------------------------
    def _analyze_one(self, content: str, input_type: str) -> tuple[dict[str, Any], QrPayload]:
        rules = self.url_service.rules
        payload = classify(content, rules.dangerous_schemes)

        if payload.content_type in ("url", "dangerous"):
            try:
                analysis, result = self.url_service.analyze_link(payload.raw)
                return self.url_service.build_response(analysis, result, input_type), payload
            except URLValidationError:
                payload = QrPayload("text", payload.raw, {}, payload.raw)  # e.g. "www." only

        indicators = payload_indicators(payload, rules)
        if payload.text_for_rules:
            try:
                response = self.message_service.analyze_text(
                    payload.text_for_rules, input_type=input_type, extra_indicators=indicators
                )
                return response, payload
            except TextNotAnalyzableError:
                pass  # e.g. a QR code holding only a number: fall through to payload checks

        result = score_indicators(
            self.url_service.scoring,
            indicators,
            applicable_modules={"url_qr"},
            context=ScoringContext(
                unverified_safe_is_low_confidence=False,
                allow_trusted_domain_verification=False,
                unverified_message=UNVERIFIED_QR_TEXT,
            ),
        )
        response = {
            "input_type": input_type,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "verification": result.verification,
            "summary": summary_for(result.risk_level, result.verification["status"], "qr"),
            "categories": result.categories,
            "indicators": result.indicators,
            "recommendation": recommendation_for(
                result.risk_level, result.verification["status"], result.indicator_ids, "qr"
            ),
            "score_breakdown": result.breakdown,
            "threat_intel": {
                "checked": False,
                "providers": [],
                "note": "Threat-intelligence lookups apply to web links only.",
            },
            "disclaimer": DISCLAIMER,
        }
        return response, payload

    @staticmethod
    def _summaries(results: list[tuple[dict[str, Any], QrPayload]], chosen: int) -> list[dict]:
        return [
            {
                "index": i + 1,
                "content_type": payload.content_type,
                "decoded_content": safe_display(payload),
                "risk_score": response["risk_score"],
                "risk_level": response["risk_level"],
                "scored": i == chosen,
            }
            for i, (response, payload) in enumerate(results)
        ]
