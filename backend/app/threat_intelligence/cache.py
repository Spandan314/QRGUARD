"""Small thread-safe TTL cache for provider results (in memory, per process).

Keys are SHA-256 hashes of provider name + URL, so cached URLs are not kept in clear text.
Only definitive answers are cached: LISTED/PARTIAL for longer, NOT_LISTED briefly (a new
threat may be added to a list at any time). UNAVAILABLE/ERROR/DISABLED are never cached.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from app.threat_intelligence.base import ProviderResult, TIStatus


def cache_key(provider: str, url: str) -> str:
    return hashlib.sha256(f"{provider}\0{url}".encode()).hexdigest()


class TTLCache:
    def __init__(
        self,
        listed_ttl: float,
        not_listed_ttl: float,
        max_entries: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.listed_ttl = listed_ttl
        self.not_listed_ttl = not_listed_ttl
        self.max_entries = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, ProviderResult]] = OrderedDict()
        self._lock = threading.Lock()

    def _ttl(self, result: ProviderResult) -> float:
        if result.status in (TIStatus.LISTED, TIStatus.PARTIAL):
            return self.listed_ttl
        if result.status == TIStatus.NOT_LISTED:
            return self.not_listed_ttl
        return 0

    def get(self, key: str) -> ProviderResult | None:
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            expires, result = entry
            if self._clock() >= expires:
                del self._data[key]
                return None
            return result

    def put(self, key: str, result: ProviderResult) -> None:
        ttl = self._ttl(result)
        if ttl <= 0:
            return
        with self._lock:
            self._data[key] = (self._clock() + ttl, result)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)
