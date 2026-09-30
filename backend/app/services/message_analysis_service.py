"""Scam-message pipeline: preprocess -> message rules -> links (URL pipeline) -> score.

Scoring design (docs/risk-scoring.md, "Scam messages"):
* The message text is the PRIMARY evidence. Links found in it are ADDITIONAL evidence:
  they can raise the score but never lower it:
      final = max(text score, weighted score over text + link (+ threat intel), minimum-score rules)
* Only the riskiest link's indicators and threat-intel results are scored (other links are
  listed but add nothing), so evidence from several links is never summed.
* Link words are removed from the text before the message rules run, so nothing is counted by
  both the message analyzer and the URL analyzer.
* A trusted link never VERIFIES a message: only threat intelligence can.

Privacy: the message text is never logged or stored; only short matched phrases are returned.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.analyzers.message_analyzer import analyze_message
from app.analyzers.scam_rules import ScamRules
from app.analyzers.text_preprocessor import ExtractedLink, PreprocessedText, preprocess
from app.analyzers.url_normalizer import URLValidationError
from app.scoring.engine import ScoreResult, ScoringContext, score_indicators
from app.scoring.indicator import Indicator
from app.scoring.recommendations import DISCLAIMER, recommendation_for, summary_for
from app.services.url_analysis_service import UrlAnalysis, UrlAnalysisService

UNVERIFIED_TEXT = {
    "message": "There is insufficient evidence to establish trust. A SAFE result does not "
    "guarantee that the message is genuine.",
    "screenshot": "There is insufficient evidence to establish trust. A SAFE result does not "
    "guarantee that the content of the screenshot is genuine.",
    "qr": "There is insufficient evidence to establish trust. A SAFE result does not guarantee "
    "that the QR code is safe.",
}


# Message evidence that turns a UPI payment QR into the "scan to receive money" scam.
RECEIVE_PRETEXT_IDS = {"MSG_UPI_PIN_TO_RECEIVE", "MSG_PRIZE_REWARD", "MSG_REFUND_PRETEXT"}


class TextNotAnalyzableError(ValueError):
    """The text has (almost) no letters and no links (e.g. only emojis or numbers)."""


@dataclass
class LinkResult:
    text: str
    analysis: UrlAnalysis | None
    result: ScoreResult | None
    error: str | None = None
    redirect_checked: bool = False
    source: str = "text"


class MessageAnalysisService:
    def __init__(self, rules: ScamRules, url_service: UrlAnalysisService) -> None:
        self.rules = rules
        self.url_service = url_service

    def analyze(self, text: str) -> dict[str, Any]:
        """Analyse a pasted message (POST /api/analyze/message)."""
        return self.analyze_text(text)

    def analyze_text(
        self,
        text: str,
        *,
        input_type: str = "message",
        extra_indicators: list[Indicator] | None = None,
        extra_low_confidence_reasons: list[str] | None = None,
        extra_analysis: dict[str, Any] | None = None,
        extra_links: list[str] | None = None,
        upi_qr_indicators: list[Indicator] | None = None,
    ) -> dict[str, Any]:
        """Run the scam-message pipeline on any text (pasted, or extracted from a screenshot).

        Other inputs (e.g. OCR) may add their own informational indicators and confidence
        reasons, but the message rules, link analysis and scoring are always these same ones.
        ``extra_links`` are links decoded from QR codes in a screenshot (analysed like links in
        the text). ``upi_qr_indicators`` describe a UPI payment QR shown with the text.
        """
        pre = preprocess(text, self.rules)
        for link in extra_links or []:
            if all(link != existing.text for existing in pre.links):
                pre.links.append(ExtractedLink(link, deobfuscated=False, source="qr"))
        settings = self.rules.settings
        if pre.letter_count < settings.min_letters and not pre.links:
            raise TextNotAnalyzableError(
                "The message has too little text to analyse. Paste the full message text."
            )

        findings = analyze_message(pre, self.rules)
        links = self._analyze_links(pre)
        analysed = [link for link in links if link.result is not None]
        riskiest = max(analysed, key=lambda link: link.result.risk_score, default=None)

        indicators = [*findings.indicators, *(extra_indicators or [])]
        ti_results = []
        applicable = {"message"}
        if upi_qr_indicators:
            # A UPI payment QR is extra evidence (url_qr module): it can raise, never lower.
            applicable.add("url_qr")
            indicators.extend(upi_qr_indicators)
            if findings.ids & RECEIVE_PRETEXT_IDS:
                indicators.append(
                    Indicator("QR_UPI_RECEIVE_CONTEXT", "UPI QR + money-to-receive text")
                )
        incomplete = False
        if riskiest is not None:
            applicable.add("url_qr")
            domain = riskiest.analysis.parsed.registrable_domain or "link"
            for indicator in riskiest.analysis.indicators:
                evidence = f"{domain}: {indicator.evidence}" if indicator.evidence else domain
                indicators.append(Indicator(indicator.id, evidence))
            ti_results = riskiest.analysis.ti_results
            incomplete = riskiest.analysis.incomplete_checks

        low_reasons = list(extra_low_confidence_reasons or [])
        if len(text.strip()) < settings.short_text_chars:
            low_reasons.append("very short message")
        if "MSG_LANGUAGE_NOT_SUPPORTED" in findings.ids:
            low_reasons.append("language not fully supported")

        result = score_indicators(
            self.url_service.scoring,
            indicators,
            applicable_modules=applicable,
            ti_results=ti_results,
            context=ScoringContext(
                incomplete_checks=incomplete,
                low_confidence_reasons=low_reasons,
                unverified_safe_is_low_confidence=False,
                allow_trusted_domain_verification=False,
                unverified_message=UNVERIFIED_TEXT.get(input_type, UNVERIFIED_TEXT["message"]),
            ),
            primary_modules={"message"},
        )
        response = self._response(pre, findings, links, riskiest, result, low_reasons, input_type)
        if extra_analysis:
            response["analysis"] = {**extra_analysis, **response["analysis"]}
        return response

    # ----- links ---------------------------------------------------------------------------
    def _analyze_links(self, pre: PreprocessedText) -> list[LinkResult]:
        settings = self.rules.settings
        results: list[LinkResult] = []
        redirect_budget = settings.max_links_redirect_checked
        for index, link in enumerate(pre.links):
            if index >= settings.max_links_analyzed:
                results.append(
                    LinkResult(
                        link.text, None, None, "not analysed (limit reached)", source=link.source
                    )
                )
                continue
            try:
                analysis, result = self.url_service.analyze_link(
                    link.text, resolve_redirects=redirect_budget > 0
                )
            except URLValidationError as exc:
                results.append(LinkResult(link.text, None, None, exc.code, source=link.source))
                continue
            checked = analysis.redirects.get("checked", False)
            if checked:
                redirect_budget -= 1
            results.append(LinkResult(link.text, analysis, result, None, checked, link.source))
        return results

    # ----- response ------------------------------------------------------------------------
    def _response(
        self,
        pre: PreprocessedText,
        findings,
        links: list[LinkResult],
        riskiest: LinkResult | None,
        result: ScoreResult,
        low_reasons: list[str],
        input_type: str,
    ) -> dict[str, Any]:
        ti_configured = self.url_service.threat_intel.configured
        link_rows = []
        for link in links:
            row: dict[str, Any] = {
                "url": link.text,
                "found_in": link.source,
                "scored": link is riskiest,
            }
            if link.result is not None:
                row.update(
                    {
                        "normalized_url": link.analysis.parsed.normalized,
                        "domain": link.analysis.parsed.registrable_domain or None,
                        "risk_score": link.result.risk_score,
                        "risk_level": link.result.risk_level,
                        "indicator_ids": [i["id"] for i in link.result.indicators],
                        "redirects": link.analysis.redirects,
                    }
                )
            else:
                row["error"] = link.error
            link_rows.append(row)

        return {
            "input_type": input_type,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "verification": result.verification,
            "summary": summary_for(result.risk_level, result.verification["status"], input_type),
            "categories": result.categories,
            "indicators": result.indicators,
            "recommendation": recommendation_for(
                result.risk_level, result.verification["status"], result.indicator_ids, input_type
            ),
            "score_breakdown": result.breakdown,
            "threat_intel": {
                "checked": ti_configured and riskiest is not None,
                "providers": [
                    r.to_public_dict() for r in (riskiest.analysis.ti_results if riskiest else [])
                ],
                "note": self.url_service.threat_intel.note(
                    riskiest.analysis.ti_results if riskiest else [],
                    "Threat-intelligence lookups are not enabled; links were analysed by their "
                    "structure only.",
                ),
            },
            "analysis": {
                "text_length": pre.char_count,
                "language": {
                    "script": "latin"
                    if pre.non_latin_ratio <= self.rules.settings.unsupported_script_ratio
                    else "other",
                    "supported": "MSG_LANGUAGE_NOT_SUPPORTED" not in findings.ids,
                },
                "preprocessing": {
                    "hidden_characters_removed": pre.hidden_characters,
                    "links_found": len(pre.links),
                    "links_deobfuscated": pre.links_deobfuscated,
                },
                "low_confidence_reasons": low_reasons,
                "matched_phrases": [m.to_dict() for m in findings.matches],
                "links": link_rows,
                "entities": pre.entities,
            },
            "disclaimer": DISCLAIMER,
        }
