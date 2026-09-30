"""ThreatIntelService: parallel providers, time budget, cache, disabled providers."""

import time

from app.threat_intelligence.base import ProviderResult, TIStatus
from app.threat_intelligence.cache import TTLCache, cache_key
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.service import ThreatIntelService
from tests.fakes import BrokenProvider, FakeHttp, FakeProvider, SlowProvider

URL = "https://phish.example/login"


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_multiple_providers_keep_their_order():
    service = ThreatIntelService(
        [
            FakeProvider("a", TIStatus.NOT_LISTED),
            FakeProvider("b", TIStatus.LISTED, "phishing"),
            FakeProvider("c", TIStatus.UNAVAILABLE),
        ]
    )
    assert [(r.provider, r.status) for r in service.check(URL, "phish.example")] == [
        ("a", "not_listed"),
        ("b", "listed"),
        ("c", "unavailable"),
    ]


def test_disabled_provider_is_reported_and_never_called():
    http = FakeHttp()
    service = ThreatIntelService([UrlhausProvider("", http=http)])
    assert not service.configured
    assert service.check(URL, "")[0].status == TIStatus.DISABLED
    assert http.requests == []
    assert service.status() == [{"provider": "urlhaus", "enabled": False, "external": True}]


def test_slow_provider_hits_the_budget_and_analysis_continues():
    fast = FakeProvider("fast", TIStatus.NOT_LISTED)
    service = ThreatIntelService([SlowProvider(delay=2), fast], budget_seconds=0.2)
    start = time.monotonic()
    results = service.check(URL, "")
    assert time.monotonic() - start < 1.5
    assert (results[0].status, results[0].detail) == (TIStatus.UNAVAILABLE, "timeout")
    assert results[1].status == TIStatus.NOT_LISTED


def test_crashing_provider_becomes_unavailable():
    results = ThreatIntelService([BrokenProvider()]).check(URL, "")
    assert results[0].status == TIStatus.UNAVAILABLE


def test_cache_hit_skips_the_provider():
    provider = FakeProvider("feed", TIStatus.LISTED, "phishing")
    service = ThreatIntelService([provider], cache=TTLCache(100, 10))
    first = service.check(URL, "")[0]
    second = service.check(URL, "")[0]
    assert provider.checked == [URL]
    assert not first.cached and second.cached
    assert second.to_public_dict()["cached"] is True
    assert (second.status, second.threat_type) == (TIStatus.LISTED, "phishing")


def test_cache_expiry():
    clock = Clock()
    provider = FakeProvider("feed", TIStatus.NOT_LISTED)
    service = ThreatIntelService([provider], cache=TTLCache(100, 10, clock=clock))
    service.check(URL, "")
    clock.now += 9
    service.check(URL, "")
    assert len(provider.checked) == 1
    clock.now += 2  # not_listed entries live 10 s here
    service.check(URL, "")
    assert len(provider.checked) == 2


def test_failures_are_never_cached():
    provider = FakeProvider("feed", TIStatus.UNAVAILABLE)
    service = ThreatIntelService([provider], cache=TTLCache(100, 10))
    service.check(URL, "")
    service.check(URL, "")
    assert len(provider.checked) == 2


def test_cache_ttls_and_size_limit():
    clock = Clock()
    cache = TTLCache(listed_ttl=100, not_listed_ttl=10, max_entries=2, clock=clock)
    cache.put("a", ProviderResult("p", TIStatus.LISTED))
    cache.put("b", ProviderResult("p", TIStatus.NOT_LISTED))
    cache.put("x", ProviderResult("p", TIStatus.ERROR))  # never cached
    assert len(cache) == 2
    clock.now += 50
    assert cache.get("a") is not None and cache.get("b") is None
    cache.put("c", ProviderResult("p", TIStatus.PARTIAL))
    cache.put("d", ProviderResult("p", TIStatus.PARTIAL))
    assert cache.get("a") is None  # oldest evicted


def test_cache_keys_do_not_contain_the_url():
    key = cache_key("feed", URL)
    assert "phish" not in key and len(key) == 64


def test_note_is_honest_about_coverage():
    service = ThreatIntelService([FakeProvider("feed", TIStatus.NOT_LISTED)])
    demo_only = [ProviderResult("feed", TIStatus.NOT_LISTED, limited=True)]
    assert "demo blocklist" in service.note(demo_only, "none")
    real = [ProviderResult("feed", TIStatus.NOT_LISTED)]
    assert "does not mean a link is safe" in service.note(real, "none")
    assert ThreatIntelService([]).note([], "no sources") == "no sources"


def test_providers_replaced_after_construction_still_run():
    service = ThreatIntelService([])
    service.providers = [FakeProvider("late", TIStatus.NOT_LISTED)]
    assert service.check(URL, "")[0].status == TIStatus.NOT_LISTED
