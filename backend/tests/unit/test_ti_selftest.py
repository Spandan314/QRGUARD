"""scripts/ti_selftest.py with fake HTTP: it never calls a provider WORKING without an answer."""

import pytest

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.phishtank import PhishTankProvider
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider
from scripts import ti_selftest
from tests.fakes import FakeHttp

KEY = "selftest-key-not-real"


class GsbHttp:
    """Lists only the official test page, like the real service."""

    def __init__(self, list_test_page: bool = True, test_page_status: int = 200) -> None:
        self.list_test_page = list_test_page
        self.test_page_status = test_page_status

    def request(self, method, url, *, headers=None, body=None, timeout):
        if b"testsafebrowsing" in (body or b""):
            if self.test_page_status != 200:
                return HttpResponse(self.test_page_status, {})
            if self.list_test_page:
                return HttpResponse(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
        return HttpResponse(200, {})


def test_nothing_configured_is_reported_as_off():
    code, outcomes = ti_selftest.run(ti_selftest.build_providers({}))
    assert code == 2 and not any(o.configured for o in outcomes)
    assert {o.label for o in outcomes} == {ti_selftest.NOT_CONFIGURED}
    assert outcomes[0].detail == "not configured: set GOOGLE_SAFE_BROWSING_API_KEY"


def test_a_working_safe_browsing_key_must_list_the_official_test_page():
    code, outcomes = ti_selftest.run([SafeBrowsingProvider(KEY, http=GsbHttp())])
    assert code == 0 and outcomes[0].working and outcomes[0].label == ti_selftest.WORKING
    assert "official test threat: listed" in outcomes[0].detail


def test_safe_browsing_that_does_not_list_the_test_page_fails():
    code, outcomes = ti_selftest.run(
        [SafeBrowsingProvider(KEY, http=GsbHttp(list_test_page=False))]
    )
    assert code == 1 and not outcomes[0].working  # it answered, but missed the test threat
    assert outcomes[0].label == ti_selftest.FAILED


def test_rejected_key_or_timeout_is_never_a_pass():
    code, outcomes = ti_selftest.run(
        [
            UrlhausProvider(KEY, http=FakeHttp(401, {})),
            UrlhausProvider(KEY, http=FakeHttp(error="timeout")),
        ]
    )
    assert code == 1  # one provider FAILED
    assert [o.detail for o in outcomes] == [
        "harmless lookup: error (auth failed: HTTP 401)",
        "harmless lookup: unavailable (timeout)",
    ]
    assert [o.label for o in outcomes] == [ti_selftest.FAILED, ti_selftest.NOT_VERIFIED]
    assert not any(o.working for o in outcomes)


def _vt(status=200):
    stats = {"malicious": 0, "suspicious": 0, "harmless": 60}
    return FakeHttp(status, {"data": {"attributes": {"last_analysis_stats": stats}}})


@pytest.mark.parametrize(
    ("provider", "label"),
    [
        # Rejected or invalid credentials: the provider answered with an error.
        (UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": "unknown_auth_key"})), "FAILED"),
        (UrlhausProvider(KEY, http=FakeHttp(403, None)), "FAILED"),
        (SafeBrowsingProvider(KEY, http=FakeHttp(400, {"error": {"code": 400}})), "FAILED"),
        # Rate limit / quota: reported separately, never as a bad key.
        (UrlhausProvider(KEY, http=FakeHttp(429, {})), "RATE LIMITED"),
        (PhishTankProvider("", http=FakeHttp(509, None), anonymous=True), "RATE LIMITED"),
        (VirusTotalProvider(KEY, http=_vt(), max_per_minute=0), "RATE LIMITED"),  # "quota"
        # No usable answer: says nothing about the key.
        (VirusTotalProvider(KEY, http=FakeHttp(error="timeout")), "NOT VERIFIED"),
        (UrlhausProvider(KEY, http=FakeHttp(error=True)), "NOT VERIFIED"),  # network error
        (PhishTankProvider("", http=FakeHttp(503, {}), anonymous=True), "NOT VERIFIED"),
        (UrlhausProvider(KEY, http=FakeHttp(200, {"nonsense": 1})), "NOT VERIFIED"),
    ],
)
def test_each_failure_gets_its_own_label(provider, label):
    code, outcomes = ti_selftest.run([provider])
    assert outcomes[0].label == label and not outcomes[0].working
    assert code == (1 if label == "FAILED" else 3)


def test_safe_browsing_test_threat_lookup_rate_limited_is_not_a_failure():
    code, outcomes = ti_selftest.run(
        [SafeBrowsingProvider(KEY, http=GsbHttp(test_page_status=429))]
    )
    assert code == 3 and outcomes[0].label == ti_selftest.RATE_LIMITED
    assert "official test threat: unavailable (rate limited)" in outcomes[0].detail


def test_a_failure_wins_over_unverified_providers_in_the_exit_code():
    code, outcomes = ti_selftest.run(
        [
            UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": "no_results"})),
            VirusTotalProvider(KEY, http=FakeHttp(429, {})),
            SafeBrowsingProvider(KEY, http=FakeHttp(403, None)),
        ]
    )
    assert [o.label for o in outcomes] == ["WORKING", "RATE LIMITED", "FAILED"]
    assert code == 1


def test_unverified_providers_print_labels_and_never_the_key(capsys, monkeypatch):
    providers = [
        UrlhausProvider(KEY, http=FakeHttp(error="timeout")),
        VirusTotalProvider(KEY, http=FakeHttp(429, {})),
        PhishTankProvider("", http=FakeHttp()),  # not configured
    ]
    monkeypatch.setattr(ti_selftest, "build_providers", lambda env: providers)
    assert ti_selftest.main() == 3
    out = capsys.readouterr().out
    assert "NOT VERIFIED    urlhaus" in out
    assert "RATE LIMITED    virustotal" in out
    assert "NOT CONFIGURED  phishtank" in out
    assert "does not prove a key is wrong" in out
    assert KEY not in out


def test_urlhaus_no_results_is_working(capsys, monkeypatch):
    provider = UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": "no_results"}))
    monkeypatch.setattr(ti_selftest, "build_providers", lambda env: [provider])
    assert ti_selftest.main() == 0
    out = capsys.readouterr().out
    assert "WORKING         urlhaus" in out and KEY not in out
    assert TIStatus.NOT_LISTED.value in out
