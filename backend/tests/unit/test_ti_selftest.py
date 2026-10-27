"""scripts/ti_selftest.py with fake HTTP: it never calls a provider WORKING without an answer."""

from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.http import HttpResponse
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from scripts import ti_selftest
from tests.fakes import FakeHttp

KEY = "selftest-key-not-real"


class GsbHttp:
    """Lists only the official test page, like the real service."""

    def __init__(self, list_test_page: bool = True) -> None:
        self.list_test_page = list_test_page

    def request(self, method, url, *, headers=None, body=None, timeout):
        if self.list_test_page and b"testsafebrowsing" in (body or b""):
            return HttpResponse(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
        return HttpResponse(200, {})


def test_nothing_configured_is_reported_as_off():
    code, outcomes = ti_selftest.run(ti_selftest.build_providers({}))
    assert code == 2 and not any(o.configured for o in outcomes)
    assert outcomes[0].detail == "not configured: set GOOGLE_SAFE_BROWSING_API_KEY"


def test_a_working_safe_browsing_key_must_list_the_official_test_page():
    code, outcomes = ti_selftest.run([SafeBrowsingProvider(KEY, http=GsbHttp())])
    assert code == 0 and outcomes[0].working
    assert "official test threat: listed" in outcomes[0].detail


def test_safe_browsing_that_does_not_list_the_test_page_fails():
    code, outcomes = ti_selftest.run(
        [SafeBrowsingProvider(KEY, http=GsbHttp(list_test_page=False))]
    )
    assert code == 1 and not outcomes[0].working


def test_rejected_key_or_timeout_is_a_failure_not_a_pass():
    code, outcomes = ti_selftest.run(
        [
            UrlhausProvider(KEY, http=FakeHttp(401, {})),
            UrlhausProvider(KEY, http=FakeHttp(error="timeout")),
        ]
    )
    assert code == 1
    assert [o.detail for o in outcomes] == [
        "harmless lookup: error (auth failed: HTTP 401)",
        "harmless lookup: unavailable (timeout)",
    ]


def test_urlhaus_no_results_is_working(capsys, monkeypatch):
    provider = UrlhausProvider(KEY, http=FakeHttp(200, {"query_status": "no_results"}))
    monkeypatch.setattr(ti_selftest, "build_providers", lambda env: [provider])
    assert ti_selftest.main() == 0
    out = capsys.readouterr().out
    assert "WORKING  urlhaus" in out and KEY not in out
    assert TIStatus.NOT_LISTED.value in out
