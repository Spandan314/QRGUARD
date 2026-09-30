"""Risk-scoring engine: turns indicators into an explainable score, level and confidence.

Algorithm (all numbers come from scoring_config.yaml):

1. Threat-intel results become ONE indicator: any LISTED -> TI_LISTED, else any
   PARTIAL -> TI_PARTIAL. NOT_LISTED / UNAVAILABLE / DISABLED add nothing: absence from a list
   is not evidence.
2. Indicators are grouped by module. Inside a module, positive points per category are
   capped (category_caps); the module score is the sum, clamped to 0..100.
3. Weighted average over APPLICABLE modules only:
       weighted = sum(w_m * score_m) / sum(w_m)
   A module is applicable if the caller analysed it or it produced an indicator. So a
   URL-only check is not diluted by missing message/OCR modules.
4. Primary evidence (messages): when the caller names ``primary_modules`` (e.g. the message
   text), additional evidence (links, threat intel) may RAISE the score but never lower it:
       base = max(primary_score, weighted)
5. Floors: the highest ``floor`` among present indicators is a minimum final score.
       final = max(base, floor)
6. Level (from the score ONLY): >= malicious -> MALICIOUS, >= suspicious -> SUSPICIOUS,
   otherwise SAFE. SAFE means "no significant suspicious indicators", not "guaranteed safe".
7. Verification (reported separately, never changes the score or level):
   VERIFIED by "threat_intelligence" when a provider lists the input as malicious, or by
   "trusted_domain_list" when the domain is trusted and nothing medium-or-worse was found
   (disabled for messages: a trusted link does not prove a message is genuine);
   otherwise UNVERIFIED ("insufficient evidence to establish trust").

Each indicator's ``score_contribution`` is the number of final-score points it added (after
caps and module weighting), so the contributions add up to the base score. A floor is
reported separately in ``score_breakdown.floor_applied``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.scoring.indicator import Indicator
from app.scoring.settings import SEVERITY_ORDER, IndicatorDefinition, ScoringSettings
from app.threat_intelligence.base import DEFINITIVE_STATUSES, ProviderResult, TIStatus

SAFE, SUSPICIOUS, MALICIOUS = "SAFE", "SUSPICIOUS", "MALICIOUS"
VERIFIED, UNVERIFIED = "VERIFIED", "UNVERIFIED"
SOURCE_THREAT_INTEL = "threat_intelligence"
SOURCE_TRUSTED_LIST = "trusted_domain_list"
MODULES = ("url_qr", "threat_intel", "message", "ocr")
FALLBACK_CATEGORY = "social_engineering_other"

# Where each piece of evidence came from, as shown in the API ("source" of an indicator).
EVIDENCE_SOURCES = ("message", "link", "qr", "threat_intelligence", "combination", "ocr")

VERIFICATION_MESSAGES = {
    SOURCE_THREAT_INTEL: "A threat-intelligence source lists this as known malicious.",
    SOURCE_TRUSTED_LIST: "The domain is on QRGUARD's list of recognised legitimate websites.",
    None: "There is insufficient evidence to establish trust. "
    "A SAFE result does not guarantee that the website is safe.",
}


class UnknownIndicatorError(KeyError):
    """An analyzer emitted an indicator ID missing from scoring_config.yaml (a bug)."""


@dataclass
class ScoringContext:
    """Extra facts that affect confidence and verification (never the score)."""

    incomplete_checks: bool = False  # e.g. a shortener's destination could not be checked
    low_confidence_reasons: list[str] = field(default_factory=list)  # e.g. "very short message"
    unverified_safe_is_low_confidence: bool = True  # URL checks: SAFE + UNVERIFIED -> LOW
    allow_trusted_domain_verification: bool = True  # False for messages
    unverified_message: str | None = None  # wording override for UNVERIFIED


@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str
    confidence: str
    indicators: list[dict[str, Any]]
    categories: list[dict[str, str]]
    breakdown: dict[str, Any]
    verification: dict[str, Any] = field(default_factory=dict)
    indicator_ids: set[str] = field(default_factory=set)


def threat_intel_indicators(results: list[ProviderResult]) -> list[Indicator]:
    listed = [r.provider for r in results if r.status == TIStatus.LISTED]
    if listed:
        return [Indicator("TI_LISTED", "Listed by: " + ", ".join(listed))]
    partial = [r.provider for r in results if r.status == TIStatus.PARTIAL]
    if partial:
        return [Indicator("TI_PARTIAL", "Flagged by: " + ", ".join(partial))]
    return []


def evidence_source(definition: IndicatorDefinition) -> str:
    """message / link / qr / threat_intelligence / combination / ocr."""
    if definition.category == "combination":
        return "combination"
    if definition.category == "qr_payload":  # UPI, Wi-Fi, phone... read from a QR code
        return "qr"
    return {"url_qr": "link", "threat_intel": "threat_intelligence"}.get(
        definition.module, definition.module
    )


def score_indicators(
    settings: ScoringSettings,
    indicators: list[Indicator],
    applicable_modules: set[str],
    ti_results: list[ProviderResult] | None = None,
    context: ScoringContext | None = None,
    primary_modules: set[str] | None = None,
) -> ScoreResult:
    ti_results = ti_results or []
    context = context or ScoringContext()
    all_indicators = [*indicators, *threat_intel_indicators(ti_results)]

    definitions: dict[str, IndicatorDefinition] = {}
    for indicator in all_indicators:
        if indicator.id not in settings.indicators:
            raise UnknownIndicatorError(indicator.id)
        definitions[indicator.id] = settings.indicators[indicator.id]

    modules = set(applicable_modules) | {definitions[i.id].module for i in all_indicators}
    weight_of = settings.module_weights.of

    # ---- 1. points per indicator inside its module (category caps) --------------------------
    positive_sum: dict[tuple[str, str], float] = defaultdict(float)
    for ind in all_indicators:
        d = definitions[ind.id]
        if d.weight > 0:
            positive_sum[(d.module, d.category)] += d.weight

    points: list[float] = []
    for ind in all_indicators:
        d = definitions[ind.id]
        if d.weight > 0:
            cap = settings.category_caps[d.category]
            points.append(d.weight * min(1.0, cap / positive_sum[(d.module, d.category)]))
        else:
            points.append(float(d.weight))

    # ---- 2. module scores, weighted average, primary-evidence rule -------------------------
    module_raw: dict[str, float] = defaultdict(float)
    for ind, pts in zip(all_indicators, points, strict=True):
        module_raw[definitions[ind.id].module] += pts
    module_score = {m: max(0.0, min(100.0, module_raw.get(m, 0.0))) for m in modules}

    def weighted_over(selected: set[str]) -> float:
        total = sum(weight_of(m) for m in selected)
        return sum(weight_of(m) * module_score[m] for m in selected) / total if total else 0.0

    weighted = weighted_over(modules)
    primary = (primary_modules or set()) & modules
    primary_score = weighted_over(primary) if primary else None
    if primary_score is not None and primary_score >= weighted:
        base, base_modules, rule_used = primary_score, primary, "primary_evidence"
    elif primary_score is not None:
        base, base_modules, rule_used = weighted, modules, "weighted_with_additional_evidence"
    else:
        base, base_modules, rule_used = weighted, modules, "weighted"
    base_total = sum(weight_of(m) for m in base_modules)

    contributions: list[float] = []
    for ind, pts in zip(all_indicators, points, strict=True):
        module = definitions[ind.id].module
        raw = module_raw[module]
        if module not in base_modules or raw <= 0 or not base_total:
            contributions.append(0.0)  # this evidence did not raise the score
            continue
        scale = module_score[module] / raw
        contributions.append(pts * scale * weight_of(module) / base_total)

    # ---- 3. floors ---------------------------------------------------------------------------
    floor_value, floor_id = 0, None
    for ind in all_indicators:
        floor = definitions[ind.id].floor
        if floor is not None and floor > floor_value:
            floor_value, floor_id = floor, ind.id
    final = max(base, float(floor_value))
    risk_score = int(min(100.0, final) + 0.5)
    floor_applied = None
    if floor_id is not None and floor_value > base:
        floor_applied = {
            "indicator": floor_id,
            "minimum_score": floor_value,
            "points_added": round(floor_value - base, 1),
        }

    # ---- 4. level (score only) ---------------------------------------------------------------
    severities = {ind.id: settings.severity_of(definitions[ind.id]) for ind in all_indicators}
    ids = {ind.id for ind in all_indicators}
    thresholds = settings.thresholds
    if risk_score >= thresholds.malicious:
        level = MALICIOUS
    elif risk_score >= thresholds.suspicious:
        level = SUSPICIOUS
    else:
        level = SAFE

    # ---- 4b. verification (reported separately; never changes score or level) --------------
    rule = settings.verification
    blocking = SEVERITY_ORDER.index(rule.trusted_blocked_by_severity)
    has_blocking = any(
        SEVERITY_ORDER.index(severities[i.id]) >= blocking
        for i in all_indicators
        if definitions[i.id].weight > 0
    )
    source: str | None
    if rule.threat_intel_indicator in ids:
        source = SOURCE_THREAT_INTEL
    elif (
        context.allow_trusted_domain_verification
        and rule.trusted_domain_indicator in ids
        and not has_blocking
    ):
        source = SOURCE_TRUSTED_LIST
    else:
        source = None
    message = VERIFICATION_MESSAGES[source]
    if source is None and context.unverified_message:
        message = context.unverified_message
    verification = {
        "status": VERIFIED if source else UNVERIFIED,
        "source": source,
        "message": message,
    }

    # ---- 5. confidence -----------------------------------------------------------------------
    # A demo-only blocklist saying "not listed" is not a real reputation check.
    ti_definitive = any(r.status in DEFINITIVE_STATUSES and not r.limited for r in ti_results)
    positive_categories = {
        definitions[i.id].category for i in all_indicators if definitions[i.id].weight > 0
    }
    if (
        "TI_LISTED" in ids
        or floor_applied
        or (level == MALICIOUS and len(positive_categories) >= 3)
    ):
        confidence = "HIGH"
    elif (
        context.incomplete_checks
        or context.low_confidence_reasons
        or (
            context.unverified_safe_is_low_confidence
            and level == SAFE
            and source is None
            and not ti_definitive
        )
    ):
        confidence = "LOW"
    else:
        confidence = "MEDIUM"

    # ---- 6. explainable output ---------------------------------------------------------------
    rows = []
    for ind, contribution in zip(all_indicators, contributions, strict=True):
        d = definitions[ind.id]
        rows.append(
            {
                "id": ind.id,
                "source": evidence_source(d),
                "severity": severities[ind.id],
                "title": d.title,
                "message": d.message,
                "evidence": ind.safe_evidence(),
                "weight": d.weight,
                "score_contribution": round(contribution, 1) + 0.0,  # +0.0 turns -0.0 into 0.0
                "module": d.module,
            }
        )
    rows.sort(key=lambda r: (-abs(r["score_contribution"]), -r["weight"]))

    # Categories describe the scam; they never add points. Only evidence that actually counted
    # (raised the score, or set the minimum score) can add a category.
    categories: list[dict[str, str]] = []
    if level in (SUSPICIOUS, MALICIOUS):
        for row in rows:
            counted = row["score_contribution"] > 0 or (
                floor_applied is not None and row["id"] == floor_applied["indicator"]
            )
            if row["weight"] <= 0 or not counted:
                continue
            for label in definitions[row["id"]].scam_categories:
                if all(c["id"] != label for c in categories):
                    categories.append({"id": label, "label": settings.scam_categories[label]})
        if not categories:
            categories.append(
                {"id": FALLBACK_CATEGORY, "label": settings.scam_categories[FALLBACK_CATEGORY]}
            )

    sources = []
    for source_name in EVIDENCE_SOURCES:
        members = [r for r in rows if r["source"] == source_name]
        if members:
            sources.append(
                {
                    "source": source_name,
                    "points": round(sum(r["score_contribution"] for r in members), 1) + 0.0,
                    "indicator_ids": [r["id"] for r in members],
                }
            )

    breakdown = {
        "modules": [
            {
                "module": module,
                "applicable": module in modules,
                "module_score": round(module_score[module], 1) if module in modules else None,
                "weight": weight_of(module),
                "effective_weight": (
                    round(weight_of(module) / base_total, 3)
                    if module in base_modules and base_total
                    else 0.0
                ),
            }
            for module in MODULES
        ],
        "primary_score": round(primary_score, 1) if primary_score is not None else None,
        "weighted_score": round(weighted, 1),
        "rule_used": rule_used,
        "floor_applied": floor_applied,
        "final_score": risk_score,
        "sources": sources,
    }
    return ScoreResult(
        risk_score, level, confidence, rows, categories, breakdown, verification, ids
    )
