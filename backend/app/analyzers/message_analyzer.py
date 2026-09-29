"""Rule-based scam-message analysis (explainable; no machine learning).

Input: a PreprocessedText. Output: message indicators plus the matched phrases that explain them.

Rules that prevent double counting and keyword-only decisions:
* A piece of text supports ONE indicator only (rules are tried in priority order; a later
  match that overlaps words already used is ignored).
* Each indicator counts once per message.
* "Negatable" requests are ignored when negated ("never share your OTP").
* Link words are not in the detection text at all (links are analysed by the URL module).
* Combination indicators fire only when every group of the combination is present.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analyzers.scam_rules import LINK_TOKEN, CompiledRule, ScamRules
from app.analyzers.text_preprocessor import LINK, PHONE, PreprocessedText, display
from app.scoring.indicator import Indicator

_CLAUSE_BREAKS = ",;:()"


@dataclass
class PhraseMatch:
    indicator: str
    sentence: int  # 1-based
    start: int
    end: int
    phrase: str

    def to_dict(self) -> dict[str, Any]:
        return {"indicator": self.indicator, "phrase": self.phrase, "sentence": self.sentence}


@dataclass
class MessageFindings:
    indicators: list[Indicator] = field(default_factory=list)
    matches: list[PhraseMatch] = field(default_factory=list)

    @property
    def ids(self) -> set[str]:
        return {i.id for i in self.indicators}


def _is_negated(sentence: str, start: int, end: int, rules: ScamRules) -> bool:
    """Negation word in the 3 words before the match (same clause) or inside the match."""
    before = sentence[:start]
    for mark in _CLAUSE_BREAKS:
        before = before.rsplit(mark, 1)[-1]
    last_words = " ".join(before.split()[-3:])
    return bool(rules.negation.search(last_words) or rules.negation.search(sentence[start:end]))


def _evidence(text: str, limit: int) -> str:
    text = display(" ".join(text.split()))
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _match_rule(
    rule: CompiledRule, index: int, sentence: str, taken: list[tuple[int, int]], rules: ScamRules
) -> PhraseMatch | None:
    limit = rules.settings.evidence_max_chars
    for pattern in rule.patterns:
        for match in pattern.finditer(sentence):
            start, end = match.span()
            if any(s < end and start < e for s, e in taken):
                continue  # these words already support a stronger indicator
            if rule.negatable and _is_negated(sentence, start, end, rules):
                continue
            return PhraseMatch(rule.id, index + 1, start, end, _evidence(match.group(0), limit))
    return None


def analyze_message(text: PreprocessedText, rules: ScamRules) -> MessageFindings:
    findings = MessageFindings()
    first_match: dict[str, PhraseMatch] = {}
    settings = rules.settings

    # 1. Pattern rules, sentence by sentence, in priority order.
    for index, sentence in enumerate(text.sentences):
        taken: list[tuple[int, int]] = []
        for rule in rules.rules:
            match = _match_rule(rule, index, sentence, taken, rules)
            if match is None:
                continue
            taken.append((match.start, match.end))
            findings.matches.append(match)
            first_match.setdefault(rule.id, match)

    for rule in rules.rules:  # keep priority order in the output
        if rule.id in first_match:
            findings.indicators.append(Indicator(rule.id, first_match[rule.id].phrase))

    present = findings.ids

    # 2. Derived indicators (relationships between parts of the message, not words).
    for index, sentence in enumerate(text.sentences):
        if "MSG_LINK_CALL_TO_ACTION" not in present and LINK in sentence:
            verb = rules.link_action.search(sentence.replace(LINK, " "))
            if verb:
                phrase = f"{verb.group(0)} … {display(LINK)}"
                findings.indicators.append(Indicator("MSG_LINK_CALL_TO_ACTION", phrase))
                findings.matches.append(
                    PhraseMatch("MSG_LINK_CALL_TO_ACTION", index + 1, 0, 0, phrase)
                )
                present.add("MSG_LINK_CALL_TO_ACTION")
        if (
            "MSG_PHONE_CALL_TO_ACTION" not in present
            and PHONE in sentence
            and present & rules.phone_action_requires
        ):
            verb = rules.phone_action.search(sentence)
            if verb:
                phrase = f"{verb.group(0)} … {display(PHONE)}"
                findings.indicators.append(Indicator("MSG_PHONE_CALL_TO_ACTION", phrase))
                findings.matches.append(
                    PhraseMatch("MSG_PHONE_CALL_TO_ACTION", index + 1, 0, 0, phrase)
                )
                present.add("MSG_PHONE_CALL_TO_ACTION")

    if text.max_exclamation_run >= settings.exclamation_run or (
        text.exclamation_count >= settings.exclamation_total
    ):
        findings.indicators.append(
            Indicator("MSG_EXCESSIVE_PUNCTUATION", f"{text.exclamation_count} exclamation marks")
        )
    if text.letter_count >= settings.caps_min_letters and text.caps_ratio > settings.caps_ratio:
        findings.indicators.append(
            Indicator("MSG_EXCESSIVE_CAPS", f"{round(text.caps_ratio * 100)}% capital letters")
        )
    if text.hidden_characters or text.mixed_script_words:
        detail = []
        if text.hidden_characters:
            detail.append(f"{text.hidden_characters} invisible characters")
        if text.mixed_script_words:
            detail.append(f"{text.mixed_script_words} words mixing alphabets")
        findings.indicators.append(Indicator("MSG_HIDDEN_CHARACTERS", ", ".join(detail)))
    if text.non_latin_ratio > settings.unsupported_script_ratio:
        findings.indicators.append(
            Indicator(
                "MSG_LANGUAGE_NOT_SUPPORTED",
                f"{round(text.non_latin_ratio * 100)}% non-Latin letters",
            )
        )

    # 3. Combination rules: every group must be satisfied by a present indicator.
    present = findings.ids | ({LINK_TOKEN} if text.links else set())
    for combo_id, groups in rules.combinations.items():
        chosen = []
        for group in groups:
            hit = next((member for member in group if member in present), None)
            if hit is None:
                break
            chosen.append(hit)
        else:
            parts = [
                "link"
                if member == LINK_TOKEN
                else member.removeprefix("MSG_").replace("_", " ").lower()
                for member in chosen
            ]
            findings.indicators.append(Indicator(combo_id, " + ".join(parts)))

    return findings
