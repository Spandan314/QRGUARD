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
from app.analyzers.text_preprocessor import PreprocessedText, preprocess
from app.analyzers.url_normalizer import URLValidationError
from app.scoring.engine import ScoreResult, ScoringContext, score_indicators
from app.scoring.indicator import Indicator
from app.scoring.recommendations import DISCLAIMER, recommendation_for, summary_for
from app.services.url_analysis_service import UrlAnalysis, UrlAnalysisService

UNVERIFIED_MESSAGE_TEXT = (
    "There is insufficient evidence to establish trust. A SAFE result does not guarantee that "
    "the message is genuine."
)


class TextNotAnalyzableError(ValueError):
    """The text has (almost) no letters and no links (e.g. only emojis or numbers)."""


@dataclass
class LinkResult:
    text: str
    analysis: UrlAnalysis | None
    result: ScoreResult | None
    error: str | None = None
    redirect_checked: bool = False


class MessageAnalysisService:
    def __init__(self, rules: ScamRules, url_service: UrlAnalysisService) -> None:
        self.rules = rules
        self.url_service = url_service

    def analyze(self, text: str) -> dict[str, Any]:
        pre = preprocess(text, self.rules)
        settings = self.rules.settings
        if pre.letter_count < settings.min_letters and not pre.links:
            raise TextNotAnalyzableError(
                "The message has too little text to analyse. Paste the full message text."
            )

        findings = analyze_message(pre, self.rules)
        links = self._analyze_links(pre)
        analysed = [link for link in links if link.result is not None]
        riskiest = max(analysed, key=lambda link: link.result.risk_score, default=None)

        indicators = list(findings.indicators)
        ti_results = []
        applicable = {"message"}
        incomplete = False
        if riskiest is not None:
            applicable.add("url_qr")
            domain = riskiest.analysis.parsed.registrable_domain or "link"
            for indicator in riskiest.analysis.indicators:
                evidence = f"{domain}: {indicator.evidence}" if indicator.evidence else domain
                indicators.append(Indicator(indicator.id, evidence))
            ti_results = riskiest.analysis.ti_results
            incomplete = riskiest.analysis.incomplete_checks

        low_reasons = []
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
                unverified_message=UNVERIFIED_MESSAGE_TEXT,
            ),
            primary_modules={"message"},
        )
        return self._response(pre, findings, links, riskiest, result, low_reasons)

    # ----- links ---------------------------------------------------------------------------
    def _analyze_links(self, pre: PreprocessedText) -> list[LinkResult]:
        settings = self.rules.settings
        results: list[LinkResult] = []
        redirect_budget = settings.max_links_redirect_checked
        for index, link in enumerate(pre.links):
            if index >= settings.max_links_analyzed:
                results.append(LinkResult(link.text, None, None, "not analysed (limit reached)"))
                continue
            try:
                analysis, result = self.url_service.analyze_link(
                    link.text, resolve_redirects=redirect_budget > 0
                )
            except URLValidationError as exc:
                results.append(LinkResult(link.text, None, None, exc.code))
                continue
            checked = analysis.redirects.get("checked", False)
            if checked:
                redirect_budget -= 1
            results.append(LinkResult(link.text, analysis, result, None, checked))
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
    ) -> dict[str, Any]:
        ti_configured = self.url_service.threat_intel.configured
        link_rows = []
        for link in links:
            row: dict[str, Any] = {"url": link.text, "scored": link is riskiest}
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
            "input_type": "message",
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "verification": result.verification,
            "summary": summary_for(result.risk_level, result.verification["status"], "message"),
            "categories": result.categories,
            "indicators": result.indicators,
            "recommendation": recommendation_for(
                result.risk_level, result.verification["status"], result.indicator_ids, "message"
            ),
            "score_breakdown": result.breakdown,
            "threat_intel": {
                "checked": ti_configured and riskiest is not None,
                "providers": [
                    r.to_public_dict() for r in (riskiest.analysis.ti_results if riskiest else [])
                ],
                "note": (
                    "Not being listed in a threat database does not mean a link is safe."
                    if ti_configured
                    else "Threat-intelligence lookups are not enabled yet; links were analysed "
                    "by their structure only."
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
