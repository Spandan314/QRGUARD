"""Load and validate ``scoring_config.yaml``.

The scoring configuration is validated with Pydantic so that mistakes such as
``suspicious: 70, malicious: 60`` or weights that do not add up to 1.0 are caught
when the server starts, not silently during an analysis.
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

DEFAULT_SCORING_CONFIG_PATH = Path(__file__).with_name("scoring_config.yaml")


class ScoringConfigError(ValueError):
    """Raised when the scoring configuration file is missing or invalid."""


class Thresholds(BaseModel):
    model_config = ConfigDict(extra="forbid")

    suspicious: int = Field(ge=1, le=100)
    malicious: int = Field(ge=1, le=100)

    @model_validator(mode="after")
    def _check_order(self) -> Thresholds:
        if self.suspicious >= self.malicious:
            raise ValueError("thresholds.suspicious must be lower than thresholds.malicious")
        return self


class ModuleWeights(BaseModel):
    model_config = ConfigDict(extra="forbid")

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


class ScoringSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    thresholds: Thresholds
    module_weights: ModuleWeights


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
