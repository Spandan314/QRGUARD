"""Risk-scoring engine: turns indicators into an explainable score, level and confidence.

Algorithm (all numbers come from scoring_config.yaml):

1. Threat-intel results become indicators: any LISTED -> TI_LISTED, else any PARTIAL -> TI_PARTIAL.
   NOT_LISTED / UNAVAILABLE / DISABLED add nothing: absence from a list is not evidence.
2. Indicators are grouped by module. Inside a module, positive points per category are
   capped (category_caps); the module score is the sum, clamped to 0..100.
3. Weighted average over APPLICABLE modules only:
       weighted = sum(w_m * score_m) / sum(w_m)
   A module is applicable if the caller analysed it or it produced an indicator. So a
   URL-only check is not diluted by missing message/OCR modules.
4. Floors: the highest ``floor`` among present indicators is a minimum final score.
5. Level: >= malicious -> MALICIOUS, >= suspicious -> SUSPICIOUS, otherwise SAFE only if
   positively verified (trusted domain and nothing medium-or-worse), else UNVERIFIED.

Each indicator's ``score_contribution`` is the number of final-score points it added
(after caps and module weighting), so the contributions add up to the weighted score.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.scoring.indicator import Indicator
from app.scoring.settings import SEVERITY_ORDER, ScoringSettings
from app.threat_intelligence.base import DEFINITIVE_STATUSES, ProviderResult, TIStatus

SAFE, UNVERIFIED, SUSPICIOUS, MALICIOUS = "SAFE", "UNVERIFIED", "SUSPICIOUS", "MALICIOUS"


class UnknownIndicatorError(KeyError):
    """An analyzer emitted an indicator ID missing from scoring_config.yaml (a bug)."""


@dataclass
class ScoringContext:
    """Extra facts that affect confidence (not the score)."""

    incomplete_checks: bool = False  # e.g. a shortener's destination could not be checked


@dataclass
class ScoreResult:
    risk_score: int
    risk_level: str
    confidence: str
    indicators: list[dict[str, Any]]
    categories: list[dict[str, str]]
    breakdown: dict[str, Any]
    indicator_ids: set[str] = field(default_factory=set)


def threat_intel_indicators(results: list[ProviderResult]) -> list[Indicator]:
    listed = [r.provider for r in results if r.status == TIStatus.LISTED]
    if listed:
        return [Indicator("TI_LISTED", "Listed by: " + ", ".join(listed))]
    partial = [r.provider for r in results if r.status == TIStatus.PARTIAL]
    if partial:
        return [Indicator("TI_PARTIAL", "Flagged by: " + ", ".join(partial))]
    return []


def score_indicators(
    settings: ScoringSettings,
    indicators: list[Indicator],
    applicable_modules: set[str],
    ti_results: list[ProviderResult] | None = None,
    context: ScoringContext | None = None,
) -> ScoreResult:
    ti_results = ti_results or []
    context = context or ScoringContext()
    all_indicators = [*indicators, *threat_intel_indicators(ti_results)]

    definitions = {}
    for indicator in all_indicators:
        if indicator.id not in settings.indicators:
            raise UnknownIndicatorError(indicator.id)
        definitions[indicator.id] = settings.indicators[indicator.id]

    modules = set(applicable_modules) | {definitions[i.id].module for i in all_indicators}
    total_weight = sum(settings.module_weights.of(m) for m in modules)

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
            factor = min(1.0, cap / positive_sum[(d.module, d.category)])
            points.append(d.weight * factor)
        else:
            points.append(float(d.weight))

    # ---- 2. module scores and weighted average -----------------------------------------------
    module_raw: dict[str, float] = defaultdict(float)
    for ind, pts in zip(all_indicators, points, strict=True):
        module_raw[definitions[ind.id].module] += pts
    module_score = {m: max(0.0, min(100.0, module_raw.get(m, 0.0))) for m in modules}
    weighted = (
        sum(settings.module_weights.of(m) * module_score[m] for m in modules) / total_weight
        if total_weight
        else 0.0
    )

    contributions: list[float] = []
    for ind, pts in zip(all_indicators, points, strict=True):
        module = definitions[ind.id].module
        raw = module_raw[module]
        scale = module_score[module] / raw if raw > 0 else 0.0
        share = settings.module_weights.of(module) / total_weight if total_weight else 0.0
        contributions.append(pts * scale * share)

    # ---- 3. floors ---------------------------------------------------------------------------
    floor_value, floor_id = 0, None
    for ind in all_indicators:
        floor = definitions[ind.id].floor
        if floor is not None and floor > floor_value:
            floor_value, floor_id = floor, ind.id
    final = max(weighted, float(floor_value))
    risk_score = int(min(100.0, final) + 0.5)
    floor_applied = None
    if floor_id is not None and floor_value > weighted:
        floor_applied = {
            "indicator": floor_id,
            "minimum_score": floor_value,
            "points_added": round(floor_value - weighted, 1),
        }

    # ---- 4. level ----------------------------------------------------------------------------
    severities = {ind.id: settings.severity_of(definitions[ind.id]) for ind in all_indicators}
    ids = {ind.id for ind in all_indicators}
    thresholds = settings.thresholds
    if risk_score >= thresholds.malicious:
        level = MALICIOUS
    elif risk_score >= thresholds.suspicious:
        level = SUSPICIOUS
    else:
        verification = settings.verification
        blocking = SEVERITY_ORDER.index(verification.blocked_by_severity)
        has_blocking = any(
            SEVERITY_ORDER.index(severities[i.id]) >= blocking
            for i in all_indicators
            if definitions[i.id].weight > 0
        )
        verified = verification.safe_requires_indicator in ids and not has_blocking
        level = SAFE if verified else UNVERIFIED

    # ---- 5. confidence -----------------------------------------------------------------------
    ti_definitive = any(r.status in DEFINITIVE_STATUSES for r in ti_results)
    positive_categories = {
        definitions[i.id].category for i in all_indicators if definitions[i.id].weight > 0
    }
    if (
        "TI_LISTED" in ids
        or floor_applied
        or (level == MALICIOUS and len(positive_categories) >= 3)
    ):
        confidence = "HIGH"
    elif context.incomplete_checks or (level == UNVERIFIED and not ti_definitive):
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

    categories: list[dict[str, str]] = []
    if level in (SUSPICIOUS, MALICIOUS):
        for row in rows:
            if row["weight"] <= 0:
                continue
            for label in definitions[row["id"]].scam_categories:
                if all(c["id"] != label for c in categories):
                    categories.append({"id": label, "label": settings.scam_categories[label]})

    breakdown = {
        "modules": [
            {
                "module": module,
                "applicable": module in modules,
                "module_score": round(module_score[module], 1) if module in modules else None,
                "weight": settings.module_weights.of(module),
                "effective_weight": (
                    round(settings.module_weights.of(module) / total_weight, 3)
                    if module in modules and total_weight
                    else 0.0
                ),
            }
            for module in ("url_qr", "threat_intel", "message", "ocr")
        ],
        "weighted_score": round(weighted, 1),
        "floor_applied": floor_applied,
        "final_score": risk_score,
    }
    return ScoreResult(risk_score, level, confidence, rows, categories, breakdown, ids)
