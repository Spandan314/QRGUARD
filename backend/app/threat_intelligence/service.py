"""ThreatIntelService: runs every configured provider and never lets one crash analysis."""

from __future__ import annotations

import logging

from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus

logger = logging.getLogger("qrguard.threat_intel")


class ThreatIntelService:
    def __init__(self, providers: list[ThreatIntelProvider] | None = None) -> None:
        self.providers = providers or []

    @property
    def configured(self) -> bool:
        return bool(self.providers)

    def check(self, normalized_url: str, domain: str) -> list[ProviderResult]:
        results: list[ProviderResult] = []
        for provider in self.providers:
            if not provider.is_enabled():
                results.append(ProviderResult(provider.name, TIStatus.DISABLED))
                continue
            try:
                results.append(provider.check_url(normalized_url, domain))
            except Exception:  # a broken provider must never break the analysis
                logger.warning("threat-intel provider failed", extra={"event": provider.name})
                results.append(ProviderResult(provider.name, TIStatus.UNAVAILABLE))
        return results
