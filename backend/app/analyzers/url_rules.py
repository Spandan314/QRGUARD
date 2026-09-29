"""Load and validate the URL rule files (``app/data/url_rules.yaml`` and ``brands.yaml``).

The analyzers receive a ``UrlRules`` object instead of reading files themselves, so
tests can pass custom rules and the server fails fast at startup if a file is broken.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


class UrlRulesError(ValueError):
    """Raised when a URL rule file is missing or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _lower_list(values: list[str]) -> list[str]:
    return [value.strip().lower() for value in values if value.strip()]


class UrlLimits(_Strict):
    long_url_length: int = Field(ge=20)
    very_long_url_length: int = Field(ge=40)
    max_subdomains: int = Field(ge=1)
    max_hyphens_in_domain: int = Field(ge=1)
    special_char_ratio: float = Field(gt=0, lt=1)
    special_char_min_length: int = Field(ge=1)
    many_encoded_chars: int = Field(ge=1)


class Brand(_Strict):
    name: str
    official_domains: list[str] = Field(min_length=1)
    keywords: list[str] = Field(min_length=1)

    _lower = field_validator("official_domains", "keywords")(_lower_list)


class LookalikeSettings(_Strict):
    min_length_for_distance_1: int = Field(ge=3)
    min_length_for_distance_2: int = Field(ge=4)


class UrlRules(_Strict):
    limits: UrlLimits
    dangerous_schemes: list[str]
    non_web_schemes: list[str]
    executable_extensions: list[str]
    suspicious_tlds: list[str]
    url_shorteners: list[str]
    user_content_hosts: list[str]
    phishing_keywords: list[str]
    trusted_domains: list[str]
    local_host_suffixes: list[str]
    homoglyphs: dict[str, str]
    ascii_substitutions: dict[str, str]
    multi_char_substitutions: dict[str, str]
    lookalike: LookalikeSettings
    brands: list[Brand]

    _lower = field_validator(
        "dangerous_schemes",
        "non_web_schemes",
        "executable_extensions",
        "suspicious_tlds",
        "url_shorteners",
        "user_content_hosts",
        "phishing_keywords",
        "trusted_domains",
        "local_host_suffixes",
    )(_lower_list)

    # ----- convenience lookups ------------------------------------------------------------------
    def official_domains(self) -> dict[str, Brand]:
        """Map every official domain to its brand."""
        return {domain: brand for brand in self.brands for domain in brand.official_domains}


def _read_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise UrlRulesError(f"Rule file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise UrlRulesError(f"Rule file is not valid YAML ({path}): {exc}") from exc
    if not isinstance(data, dict):
        raise UrlRulesError(f"Rule file must be a YAML mapping: {path}")
    return data


def load_url_rules(data_dir: Path = DATA_DIR) -> UrlRules:
    """Read ``url_rules.yaml`` + ``brands.yaml`` from ``data_dir`` and validate them."""
    combined = {**_read_yaml(data_dir / "url_rules.yaml"), **_read_yaml(data_dir / "brands.yaml")}
    try:
        return UrlRules.model_validate(combined)
    except ValidationError as exc:
        raise UrlRulesError(f"Invalid URL rules in {data_dir}:\n{exc}") from exc
