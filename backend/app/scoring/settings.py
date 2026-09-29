"""Load and validate ``scoring_config.yaml``.

The scoring configuration is validated with Pydantic so that mistakes such as
``suspicious: 70, malicious: 60``, weights that do not add up to 1.0, or an
indicator pointing at an unknown category are caught when the server starts,
not silently during an analysis.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

DEFAULT_SCORING_CONFIG_PATH = Path(__file__).with_name("scoring_config.yaml")

ModuleName = Literal["url_qr", "threat_intel", "message", "ocr"]
Severity = Literal["info", "low", "medium", "high", "critical"]
SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


class ScoringConfigError(ValueError):
    """Raised when the scoring configuration file is missing or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Thresholds(_Strict):
    suspicious: int = Field(ge=1, le=100)
    malicious: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def _check_order(self) -> Thresholds:
        if self.suspicious >= self.malicious:
            raise ValueError("thresholds.suspicious must be lower than thresholds.malicious")
        return self


class ModuleWeights(_Strict):
    url_qr: float = Field(ge=0, le=1)
    threat_intel: float = Field(ge=0, le=1)
    message: float = Field(ge=0, le=1)
    ocr: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def _check_sum(self) -> ModuleWeights:
        total = self.url_qr + self.threat_intel + self.message + self.ocr
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"module_weights must add up to 1.0 (currently {total:.3f})")
        return self

    def of(self, module: str) -> float:
        return float(getattr(self, module))


class SeverityBands(_Strict):
    low: int = Field(ge=1)
    medium: int
    high: int
    critical: int

    @model_validator(mode="after")
    def _check_order(self) -> SeverityBands:
        if not self.low < self.medium < self.high < self.critical:
            raise ValueError("severity_bands must increase: low < medium < high < critical")
        return self


class Verification(_Strict):
    threat_intel_indicator: str  # VERIFIED (source threat_intelligence) when present
    trusted_domain_indicator: str  # VERIFIED (source trusted_domain_list) when present...
    trusted_blocked_by_severity: Severity  # ...and no finding this severe or worse


class IndicatorDefinition(_Strict):
    module: ModuleName
    category: str
    weight: int = Field(ge=-100, le=100)
    floor: int | None = Field(default=None, ge=1, le=100)
    scam_categories: list[str] = Field(default_factory=list)
    title: str = Field(min_length=3)
    message: str = Field(min_length=10)


class ScoringSettings(_Strict):
    version: int
    thresholds: Thresholds
    module_weights: ModuleWeights
    category_caps: dict[str, int]
    severity_bands: SeverityBands
    verification: Verification
    scam_categories: dict[str, str]
    indicators: dict[str, IndicatorDefinition]

    @model_validator(mode="after")
    def _check_references(self) -> ScoringSettings:
        for indicator_id, definition in self.indicators.items():
            if definition.category not in self.category_caps:
                raise ValueError(
                    f"indicator {indicator_id}: unknown category '{definition.category}'"
                )
            for label in definition.scam_categories:
                if label not in self.scam_categories:
                    raise ValueError(f"indicator {indicator_id}: unknown scam category '{label}'")
        for key in ("threat_intel_indicator", "trusted_domain_indicator"):
            if getattr(self.verification, key) not in self.indicators:
                raise ValueError(f"verification.{key} must be a known indicator")
        return self

    # ----- helpers used by the scoring engine --------------------------------------------------
    def severity_of(self, definition: IndicatorDefinition) -> Severity:
        """Human-facing severity, derived from the weight so it can never contradict it."""
        if definition.floor is not None:
            return "critical"
        bands = self.severity_bands
        weight = definition.weight
        if weight >= bands.critical:
            return "critical"
        if weight >= bands.high:
            return "high"
        if weight >= bands.medium:
            return "medium"
        if weight >= bands.low:
            return "low"
        return "info"


def load_scoring_settings(path: str | Path | None = None) -> ScoringSettings:
    """Read the YAML file at ``path`` (or the default file) and validate it."""
    config_path = Path(path) if path else DEFAULT_SCORING_CONFIG_PATH
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScoringConfigError(f"Scoring config not found: {config_path}") from exc
    except yaml.YAMLError as exc:
        raise ScoringConfigError(f"Scoring config is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ScoringConfigError("Scoring config must be a YAML mapping")
    try:
        return ScoringSettings.model_validate(raw)
    except ValidationError as exc:
        raise ScoringConfigError(f"Invalid scoring config ({config_path}):\n{exc}") from exc
