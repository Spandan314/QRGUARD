"""Local feed provider: offline blocklists held in memory. No URL leaves the server.

Sources, loaded once at startup:
    - app/data/threat_feeds/demo_blocklist.txt (always; reserved demo names only)
    - every *.txt file in THREAT_INTEL_FEED_DIR, e.g. OpenPhish / URLhaus plain-text dumps
      downloaded with `flask --app wsgi ti-update-feeds`

Each non-comment line is a full URL (exact match after normalisation) or a bare host name
(matches that host and its subdomains). Unparseable lines are skipped and counted.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from pathlib import Path
from urllib.parse import urlsplit

from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider, TIStatus

logger = logging.getLogger("qrguard.threat_intel")

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
DEMO_BLOCKLIST = DATA_DIR / "threat_feeds" / "demo_blocklist.txt"
MAX_FEED_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 1_000_000


class LocalFeedProvider(ThreatIntelProvider):
    name = "local_feed"
    external = False

    def __init__(
        self,
        normalize: Callable[[str], str | None],
        demo_files: Iterable[Path] = (DEMO_BLOCKLIST,),
        feed_files: Iterable[Path] = (),
        enabled: bool = True,
    ) -> None:
        self._normalize = normalize
        self._enabled = enabled
        self.urls: set[str] = set()
        self.hosts: set[str] = set()
        self.skipped = 0
        self.demo_only = True
        for path in demo_files:
            self._load(path)
        before = len(self.urls) + len(self.hosts)
        for path in feed_files:
            self._load(path)
        self.demo_only = len(self.urls) + len(self.hosts) == before

    def is_enabled(self) -> bool:
        return self._enabled

    @property
    def size(self) -> int:
        return len(self.urls) + len(self.hosts)

    def _load(self, path: Path) -> None:
        try:
            if path.stat().st_size > MAX_FEED_BYTES:
                logger.warning("feed file too large, skipped", extra={"event": "ti_feed_skip"})
                return
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            logger.warning("feed file unreadable, skipped", extra={"event": "ti_feed_skip"})
            return
        for line in lines:
            if self.size >= MAX_ENTRIES:
                break
            entry = line.split("#", 1)[0].strip()
            if not entry:
                continue
            if "/" in entry or ":" in entry:
                normalized = self._normalize(entry)
                if normalized:
                    self.urls.add(normalized)
                else:
                    self.skipped += 1
            else:
                self.hosts.add(entry.lower().rstrip("."))

    def _host_listed(self, host: str) -> bool:
        parts = host.split(".")
        return any(".".join(parts[i:]) in self.hosts for i in range(len(parts) - 1))

    def check_url(self, normalized_url: str, domain: str) -> ProviderResult:
        host = (urlsplit(normalized_url).hostname or "").lower()
        if normalized_url in self.urls or (host and self._host_listed(host)):
            return ProviderResult(self.name, TIStatus.LISTED, "blocklist", limited=self.demo_only)
        return ProviderResult(self.name, TIStatus.NOT_LISTED, limited=self.demo_only)
