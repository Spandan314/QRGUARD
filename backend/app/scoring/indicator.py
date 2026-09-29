"""The Indicator: the shared contract between analyzers and the scoring engine.

Analyzers only say WHAT they found (an indicator ID plus optional evidence).
They never assign points: weights, categories, floors and user-facing text for
each ID live in ``scoring_config.yaml``, so scoring can be tuned in one place.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_EVIDENCE_LENGTH = 120


@dataclass(frozen=True)
class Indicator:
    id: str  # e.g. "URL_IP_HOST"; must exist in scoring_config.yaml
    evidence: str | None = None  # short, user-safe detail (e.g. "bit.ly")

    def safe_evidence(self) -> str | None:
        """Evidence trimmed to a short length for display."""
        if self.evidence is None:
            return None
        text = " ".join(self.evidence.split())
        if len(text) > MAX_EVIDENCE_LENGTH:
            return text[: MAX_EVIDENCE_LENGTH - 1] + "…"
        return text
