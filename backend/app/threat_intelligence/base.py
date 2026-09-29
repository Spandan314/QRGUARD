"""Threat-intelligence interface shared by every reputation source.

Providers: local feeds (offline, default), URLhaus, Google Safe Browsing and VirusTotal
(lookup only). External providers are enabled only when their API key is set. A provider
never raises for network problems: it reports UNAVAILABLE or ERROR, and local analysis
continues. "not_listed" only means "not in that database"; it never lowers a score.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class TIStatus(StrEnum):
    LISTED = "listed"  # the provider knows this URL as malicious
    PARTIAL = "partial"  # some engines/vendors flag it, others do not
    NOT_LISTED = "not_listed"  # not in this provider's database (NOT proof of safety)
    UNAVAILABLE = "unavailable"  # timeout, rate limit, provider down
    DISABLED = "disabled"  # not configured (e.g. no API key)
    ERROR = "error"  # misconfiguration (e.g. rejected API key)


# Statuses that are an actual answer from a provider (used for confidence).
DEFINITIVE_STATUSES = {TIStatus.LISTED, TIStatus.PARTIAL, TIStatus.NOT_LISTED}


@dataclass(frozen=True)
class ProviderResult:
    provider: str
    status: TIStatus
    threat_type: str | None = None  # e.g. "phishing", "malware_download"
    detail: str | None = None  # short and safe to show, e.g. "timeout", "5/94 engines"
    # True for a source with very small coverage (the demo blocklist only). Its "not_listed"
    # answer does not count as a real reputation check when judging confidence.
    limited: bool = False
    cached: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        """What users see: provider name and outcome only (no raw provider data, no keys)."""
        data: dict[str, Any] = {"provider": self.provider, "status": self.status.value}
        if self.threat_type and self.status in (TIStatus.LISTED, TIStatus.PARTIAL):
            data["threat_type"] = self.threat_type
        if self.detail:
            data["detail"] = self.detail
        if self.limited:
            data["limited_coverage"] = True
        if self.cached:
            data["cached"] = True
        return data


class ThreatIntelProvider(ABC):
    """Base class every reputation source implements."""

    name: str = "provider"
    external: bool = False  # sends the URL to a third party (shown in /api/health)

    def is_enabled(self) -> bool:
        return True

    @abstractmethod
    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        """Look up one URL. Must not raise for network problems; return UNAVAILABLE."""
