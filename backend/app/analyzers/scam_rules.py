"""Load, validate and compile ``app/data/scam_rules.yaml``.

Validation happens once at startup:
* every pattern must compile,
* patterns with the classic catastrophic-backtracking shape ("(a+)+") are rejected (ReDoS),
* combinations may only refer to known rule IDs (or "@link").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.analyzers.url_rules import UrlRules

DEFAULT_SCAM_RULES_PATH = Path(__file__).resolve().parent.parent / "data" / "scam_rules.yaml"

# "Up to 4 words in between". Word and non-word classes are disjoint, so this cannot
# backtrack catastrophically; it is inserted by us, never written by hand in the YAML.
GAP = r"\W+(?:\w+\W+){0,4}?"
# Indicators computed in code (relationships and style), usable in combinations too.
DERIVED_IDS = frozenset(
    {
        "MSG_LINK_CALL_TO_ACTION",
        "MSG_PHONE_CALL_TO_ACTION",
        "MSG_EXCESSIVE_PUNCTUATION",
        "MSG_EXCESSIVE_CAPS",
        "MSG_HIDDEN_CHARACTERS",
        "MSG_LANGUAGE_NOT_SUPPORTED",
    }
)
LINK_TOKEN = "@link"  # noqa: S105 (a rule token, not a password)
MAX_PATTERN_LENGTH = 500
# A group that ends in a quantifier and is itself quantified: (x+)+  (x*)*  (x+){2,}  ...
_NESTED_QUANTIFIER_RE = re.compile(r"[+*}]\)[+*{]|[+*}]\)\?[+*{]")


class ScamRulesError(ValueError):
    """Raised when scam_rules.yaml is missing or invalid."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScamSettings(_Strict):
    max_links_analyzed: int = Field(ge=0, le=10)
    max_links_redirect_checked: int = Field(ge=0, le=10)
    min_letters: int = Field(ge=1)
    short_text_chars: int = Field(ge=1)
    unsupported_script_ratio: float = Field(gt=0, lt=1)
    caps_min_letters: int = Field(ge=1)
    caps_ratio: float = Field(gt=0, lt=1)
    exclamation_run: int = Field(ge=2)
    exclamation_total: int = Field(ge=2)
    evidence_max_chars: int = Field(ge=20, le=200)


class RuleSpec(_Strict):
    id: str = Field(pattern=r"^MSG_[A-Z_]+$")
    patterns: list[str] = Field(min_length=1)
    negatable: bool = False

    @field_validator("patterns")
    @classmethod
    def _check_patterns(cls, patterns: list[str]) -> list[str]:
        for pattern in patterns:
            if len(pattern) > MAX_PATTERN_LENGTH:
                raise ValueError(f"pattern too long ({len(pattern)} characters)")
            if _NESTED_QUANTIFIER_RE.search(pattern):
                raise ValueError(f"pattern has a nested quantifier (ReDoS risk): {pattern}")
        return patterns


class CombinationSpec(_Strict):
    all_of: list[list[str]] = Field(min_length=2)


class ScamRulesFile(_Strict):
    settings: ScamSettings
    negation_pattern: str
    link_action_pattern: str
    phone_action_pattern: str
    phone_action_requires: list[str]
    rules: list[RuleSpec] = Field(min_length=1)
    combinations: dict[str, CombinationSpec]


@dataclass(frozen=True)
class CompiledRule:
    id: str
    patterns: tuple[re.Pattern[str], ...]
    negatable: bool


@dataclass(frozen=True)
class ScamRules:
    settings: ScamSettings
    negation: re.Pattern[str]
    link_action: re.Pattern[str]
    phone_action: re.Pattern[str]
    phone_action_requires: frozenset[str]
    rules: tuple[CompiledRule, ...]  # in priority order
    combinations: dict[str, list[list[str]]]
    homoglyphs: dict[str, str]
    ascii_substitutions: dict[str, str]

    def rule_ids(self) -> set[str]:
        return {rule.id for rule in self.rules}


def _compile(pattern: str, where: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern.replace("{gap}", GAP), re.IGNORECASE)
    except re.error as exc:
        raise ScamRulesError(f"Invalid regular expression in {where}: {exc}") from exc


def load_scam_rules(url_rules: UrlRules, path: Path = DEFAULT_SCAM_RULES_PATH) -> ScamRules:
    """Read, validate and compile the scam rules. Brand keywords come from brands.yaml."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ScamRulesError(f"Scam rules not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ScamRulesError(f"Scam rules are not valid YAML: {exc}") from exc
    try:
        spec = ScamRulesFile.model_validate(raw)
    except ValidationError as exc:
        raise ScamRulesError(f"Invalid scam rules ({path}):\n{exc}") from exc

    ids = [rule.id for rule in spec.rules]
    if len(ids) != len(set(ids)):
        raise ScamRulesError("Duplicate rule IDs in scam_rules.yaml")
    known = set(ids) | DERIVED_IDS | {LINK_TOKEN}
    for combo_id, combo in spec.combinations.items():
        for group in combo.all_of:
            unknown = set(group) - known
            if unknown:
                raise ScamRulesError(f"{combo_id} refers to unknown rules: {sorted(unknown)}")
    if set(spec.phone_action_requires) - set(ids):
        raise ScamRulesError("phone_action_requires refers to unknown rules")

    compiled = []
    for rule in spec.rules:
        patterns = [_compile(p, rule.id) for p in rule.patterns]
        if rule.id == "MSG_BANK_REFERENCE":
            # Brand names (e.g. "sbi", "paytm") as whole words, from brands.yaml.
            words = sorted({k for b in url_rules.brands for k in b.keywords}, key=len, reverse=True)
            brand_pattern = r"\b(?:" + "|".join(re.escape(w) for w in words) + r")\b"
            patterns.append(_compile(brand_pattern, rule.id))
        compiled.append(CompiledRule(rule.id, tuple(patterns), rule.negatable))

    return ScamRules(
        settings=spec.settings,
        negation=_compile(spec.negation_pattern, "negation_pattern"),
        link_action=_compile(spec.link_action_pattern, "link_action_pattern"),
        phone_action=_compile(spec.phone_action_pattern, "phone_action_pattern"),
        phone_action_requires=frozenset(spec.phone_action_requires),
        rules=tuple(compiled),
        combinations={k: v.all_of for k, v in spec.combinations.items()},
        homoglyphs=url_rules.homoglyphs,
        ascii_substitutions=url_rules.ascii_substitutions,
    )
