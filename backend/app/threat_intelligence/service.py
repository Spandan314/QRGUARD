"""ThreatIntelService: runs every configured provider and never lets one crash analysis.

Enabled providers run in parallel. Each provider has its own network timeout, and the whole
lookup has one time budget: a provider that has not answered within the budget is reported
as UNAVAILABLE ("timeout") and the analysis continues without it. Disabled providers (no API
key) are reported as DISABLED, so the user can see which sources were really checked.
Definitive answers are cached (see cache.py). Nothing here logs URLs or API keys.
"""

from __future__ import annotations

import logging
from concurrent.futures import ALL_COMPLETED, ThreadPoolExecutor, wait

from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus
from app.threat_intelligence.cache import TTLCache, cache_key

logger = logging.getLogger("qrguard.threat_intel")

DEFAULT_BUDGET_SECONDS = 6.0


class ThreatIntelService:
    def __init__(
        self,
        providers: list[ThreatIntelProvider] | None = None,
        cache: TTLCache | None = None,
        budget_seconds: float = DEFAULT_BUDGET_SECONDS,
    ) -> None:
        self.providers = providers or []
        self.cache = cache
        self.budget_seconds = budget_seconds
        self._executor = (
            ThreadPoolExecutor(max_workers=max(2, 2 * len(self.providers)), thread_name_prefix="ti")
            if self.providers
            else None
        )

    @property
    def configured(self) -> bool:
        """True when at least one provider can actually be asked."""
        return any(p.is_enabled() for p in self.providers)

    def status(self) -> list[dict[str, object]]:
        """Provider names and whether they are enabled (for /api/health; never keys)."""
        return [
            {"provider": p.name, "enabled": p.is_enabled(), "external": p.external}
            for p in self.providers
        ]

    def note(self, results: list[ProviderResult], no_source_text: str) -> str:
        """Honest one-line summary of what the reputation check means."""
        if not self.configured:
            return no_source_text
        answered = [r for r in results if r.status in (TIStatus.NOT_LISTED, TIStatus.LISTED)]
        if (
            answered
            and all(r.limited for r in answered)
            and not any(r.status == TIStatus.LISTED for r in answered)
        ):
            return (
                "Only QRGUARD's small demo blocklist could be checked. Not being listed does "
                "not mean a link is safe."
            )
        return "Not being listed in a threat database does not mean a link is safe."

    def check(self, normalized_url: str, domain: str) -> list[ProviderResult]:
        results: dict[int, ProviderResult] = {}
        pending = {}
        for index, provider in enumerate(self.providers):
            if not provider.is_enabled():
                results[index] = ProviderResult(provider.name, TIStatus.DISABLED)
                continue
            key = cache_key(provider.name, normalized_url)
            cached = self.cache.get(key) if self.cache is not None else None
            if cached is not None:
                results[index] = ProviderResult(
                    cached.provider,
                    cached.status,
                    cached.threat_type,
                    cached.detail,
                    cached.limited,
                    cached=True,
                )
                continue
            future = self._pool().submit(self._safe_check, provider, normalized_url, domain)
            pending[future] = index

        if pending:
            done, not_done = wait(pending, timeout=self.budget_seconds, return_when=ALL_COMPLETED)
            for future in not_done:
                future.cancel()
                provider = self.providers[pending[future]]
                logger.warning(
                    "threat-intel provider timed out",
                    extra={"event": "ti_timeout", "provider": provider.name},
                )
                results[pending[future]] = ProviderResult(
                    provider.name, TIStatus.UNAVAILABLE, detail="timeout"
                )
            for future in done:
                result = future.result()  # _safe_check never raises
                results[pending[future]] = result
                if self.cache is not None:
                    self.cache.put(cache_key(result.provider, normalized_url), result)
        return [results[i] for i in sorted(results)]

    def _pool(self) -> ThreadPoolExecutor:
        if self._executor is None:  # providers were replaced after construction (tests)
            self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ti")
        return self._executor

    @staticmethod
    def _safe_check(provider: ThreatIntelProvider, url: str, domain: str) -> ProviderResult:
        try:
            return provider.check_url(url, domain)
        except Exception:  # a broken provider must never break the analysis
            logger.warning(
                "threat-intel provider failed",
                extra={"event": "ti_provider_error", "provider": provider.name},
            )
            return ProviderResult(provider.name, TIStatus.UNAVAILABLE)
