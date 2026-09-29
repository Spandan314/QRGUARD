"""Threat-intelligence interface.

Phase 3 defines only the interface. Real providers (URLhaus, Google Safe Browsing,
VirusTotal, local feeds) are added in the threat-intelligence phase. Until then no
provider is configured, and results clearly say that no reputation check was done.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum


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

    def to_public_dict(self) -> dict[str, str]:
        """What users see: provider name and outcome only (no raw provider data)."""
        data = {"provider": self.provider, "status": self.status.value}
        if self.threat_type and self.status in (TIStatus.LISTED, TIStatus.PARTIAL):
            data["threat_type"] = self.threat_type
        return data


class ThreatIntelProvider(ABC):
    """Base class every reputation source implements."""

    name: str = "provider"

    def is_enabled(self) -> bool:
        return True

    @abstractmethod
    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        """Look up one URL. Must not raise for network problems; return UNAVAILABLE."""
