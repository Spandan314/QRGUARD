"""Build the ThreatIntelService from the validated Config (the only place providers are wired)."""

from __future__ import annotations

from pathlib import Path

from app.analyzers.url_normalizer import normalize_url
from app.analyzers.url_rules import UrlRules
from app.config import Config
from app.threat_intelligence.cache import TTLCache
from app.threat_intelligence.providers.local_feed import LocalFeedProvider
from app.threat_intelligence.providers.phishtank import PhishTankProvider
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from app.threat_intelligence.service import ThreatIntelService


def feed_files(feed_dir: str) -> list[Path]:
    if not feed_dir:
        return []
    directory = Path(feed_dir)
    return sorted(directory.glob("*.txt")) if directory.is_dir() else []


def build_threat_intel(config: Config, rules: UrlRules) -> ThreatIntelService:
    def normalize(raw: str) -> str | None:
        try:
            return normalize_url(raw, rules).normalized
        except ValueError:  # URLValidationError, or urllib's own parsing errors
            return None

    timeout = config.ti_timeout_seconds
    providers = [
        LocalFeedProvider(
            normalize,
            feed_files=feed_files(config.ti_feed_dir),
            enabled=config.ti_local_feeds_enabled,
        ),
        UrlhausProvider(config.urlhaus_auth_key, timeout=timeout),
        SafeBrowsingProvider(config.google_safe_browsing_api_key, timeout=timeout),
        VirusTotalProvider(config.virustotal_api_key, timeout=timeout),
        PhishTankProvider(config.phishtank_api_key, timeout=timeout),
    ]
    cache = TTLCache(config.ti_cache_listed_seconds, config.ti_cache_not_listed_seconds)
    return ThreatIntelService(providers, cache=cache, budget_seconds=config.ti_budget_seconds)
