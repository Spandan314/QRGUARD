"""Threat-intelligence providers, with every external API replaced by FakeHttp (no network)."""

import json
from urllib.parse import parse_qs

import pytest
import urllib3

from app.analyzers.url_normalizer import normalize_url
from app.analyzers.url_rules import load_url_rules
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.http import TIHttpError, Urllib3Client
from app.threat_intelligence.providers.local_feed import LocalFeedProvider
from app.threat_intelligence.providers.phishtank import PhishTankProvider
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider, url_id
from tests.fakes import FakeHttp

KEY = "demo-key-DO-NOT-LEAK-123"
URL = "http://phish.example/login"
RULES = load_url_rules()


def normalize(raw):  # same contract as the factory: None for unusable lines
    try:
        return normalize_url(raw, RULES).normalized
    except ValueError:
        return None


# --- local feed ---------------------------------------------------------------------------------
def test_demo_blocklist_hit_and_miss():
    feed = LocalFeedProvider(normalize)
    hit = feed.check_url("http://secure-sbi-kyc-update.example/login", "")
    assert hit.status == TIStatus.LISTED and hit.limited  # demo list only
    miss = feed.check_url("https://www.wikipedia.org/", "wikipedia.org")
    assert miss.status == TIStatus.NOT_LISTED and miss.limited


def test_demo_blocklist_only_contains_reserved_names():
    feed = LocalFeedProvider(normalize)
    reserved = (".example", ".test", ".invalid")
    hosts = list(feed.hosts) + [u.split("/")[2] for u in feed.urls]
    assert hosts and all(h.endswith(reserved) for h in hosts)


def test_host_entries_match_subdomains_but_not_lookalikes():
    feed = LocalFeedProvider(normalize)
    assert feed.check_url("https://login.upi-refund-desk.example/pay", "").status == "listed"
    assert feed.check_url("https://upi-refund-desk.example.org/", "").status == "not_listed"
    assert feed.check_url("https://notupi-refund-desk.example/", "").status == "not_listed"


def test_downloaded_feed_files_are_loaded(tmp_path):
    feed_file = tmp_path / "openphish.txt"
    feed_file.write_text("# comment\nHTTP://Evil.TEST/Login\n\nbad-host.test\nhttp://[::1\n")
    feed = LocalFeedProvider(normalize, feed_files=[feed_file])
    assert not feed.demo_only
    result = feed.check_url(normalize("http://evil.test/Login"), "evil.test")
    assert result.status == TIStatus.LISTED and not result.limited
    assert feed.check_url("https://x.bad-host.test/", "").status == TIStatus.LISTED
    assert feed.skipped == 1  # the unparseable line


def test_unreadable_or_oversized_feed_is_skipped(tmp_path, monkeypatch):
    missing = tmp_path / "missing.txt"
    feed = LocalFeedProvider(normalize, feed_files=[missing])
    assert feed.demo_only
    big = tmp_path / "big.txt"
    big.write_text("x.test\n")
    monkeypatch.setattr("app.threat_intelligence.providers.local_feed.MAX_FEED_BYTES", 1)
    feed = LocalFeedProvider(normalize, demo_files=[], feed_files=[big])
    assert feed.size == 0


def test_local_feed_can_be_disabled():
    assert not LocalFeedProvider(normalize, enabled=False).is_enabled()


# --- missing key / shared HTTP behaviour --------------------------------------------------------
PROVIDERS = [UrlhausProvider, SafeBrowsingProvider, VirusTotalProvider, PhishTankProvider]


@pytest.mark.parametrize("cls", PROVIDERS)
@pytest.mark.parametrize("key", [None, "", "   "])
def test_missing_api_key_disables_the_provider_without_any_request(cls, key):
    http = FakeHttp()
    provider = cls(key, http=http)
    assert not provider.is_enabled()
    assert provider.check_url(URL, "phish.example").status == TIStatus.DISABLED
    assert http.requests == []


@pytest.mark.parametrize("cls", PROVIDERS)
@pytest.mark.parametrize(
    ("http", "status", "detail"),
    [
        (FakeHttp(error=True), TIStatus.UNAVAILABLE, "network error"),  # timeout / DNS / TLS
        (FakeHttp(429, {}), TIStatus.UNAVAILABLE, "rate limited"),
        (FakeHttp(500, None), TIStatus.UNAVAILABLE, "provider error"),
        (FakeHttp(503, {}), TIStatus.UNAVAILABLE, "provider error"),
        (FakeHttp(401, {}), TIStatus.ERROR, "configuration"),
        (FakeHttp(403, {}), TIStatus.ERROR, "configuration"),
        (FakeHttp(200, None), TIStatus.UNAVAILABLE, "unexpected response"),  # not JSON
        (FakeHttp(200, ["a", "list"]), TIStatus.UNAVAILABLE, "unexpected response"),
        (FakeHttp(200, {"nonsense": 1}), TIStatus.UNAVAILABLE, "unexpected response"),
        (FakeHttp(302, {}), TIStatus.UNAVAILABLE, "unexpected response"),
    ],
)
def test_failures_are_never_reported_as_not_listed(cls, http, status, detail, caplog):
    result = cls(KEY, http=http).check_url(URL, "phish.example")
    assert (result.status, result.detail) == (status, detail)
    assert KEY not in caplog.text and URL not in caplog.text


@pytest.mark.parametrize("cls", PROVIDERS)
def test_key_is_hidden_from_repr(cls):
    assert KEY not in repr(cls(KEY, http=FakeHttp()))


# --- URLhaus ------------------------------------------------------------------------------------
def test_urlhaus_listed_sends_only_the_url_with_auth_header():
    answer = {"query_status": "ok", "threat": "malware_download", "url_status": "online"}
    http = FakeHttp(200, answer)
    result = UrlhausProvider(KEY, http=http).check_url(URL, "phish.example")
    assert result.status == TIStatus.LISTED and result.threat_type == "malware_download"
    request = http.requests[0]
    assert request["url"] == "https://urlhaus-api.abuse.ch/v1/url/"
    assert request["headers"]["Auth-Key"] == KEY
    assert parse_qs(request["body"].decode()) == {"url": [URL]}


@pytest.mark.parametrize("status", ["no_results", "invalid_url"])
def test_urlhaus_not_listed(status):
    http = FakeHttp(200, {"query_status": status})
    assert UrlhausProvider(KEY, http=http).check_url(URL, "").status == TIStatus.NOT_LISTED


# --- Google Safe Browsing -----------------------------------------------------------------------
def test_safe_browsing_match_is_listed_and_request_contains_only_the_url():
    http = FakeHttp(200, {"matches": [{"threatType": "SOCIAL_ENGINEERING"}]})
    result = SafeBrowsingProvider(KEY, http=http).check_url(URL, "")
    assert result.status == TIStatus.LISTED and result.threat_type == "phishing"
    body = json.loads(http.requests[0]["body"])
    assert body["threatInfo"]["threatEntries"] == [{"url": URL}]
    assert http.requests[0]["url"].startswith("https://safebrowsing.googleapis.com/")


def test_safe_browsing_empty_answer_is_not_listed():
    assert SafeBrowsingProvider(KEY, http=FakeHttp(200, {})).check_url(URL, "").status == (
        TIStatus.NOT_LISTED
    )


def test_safe_browsing_malformed_matches():
    http = FakeHttp(200, {"matches": "yes"})
    assert SafeBrowsingProvider(KEY, http=http).check_url(URL, "").status == TIStatus.UNAVAILABLE


# --- VirusTotal ---------------------------------------------------------------------------------
def vt(malicious, suspicious=0, harmless=60):
    stats = {"malicious": malicious, "suspicious": suspicious, "harmless": harmless}
    return FakeHttp(200, {"data": {"attributes": {"last_analysis_stats": stats}}})


@pytest.mark.parametrize(
    ("http", "status"),
    [
        (vt(5), TIStatus.LISTED),
        (vt(3), TIStatus.LISTED),
        (vt(2), TIStatus.PARTIAL),  # vendors disagree: weaker evidence
        (vt(0, suspicious=3), TIStatus.PARTIAL),
        (vt(0, suspicious=1), TIStatus.NOT_LISTED),
        (FakeHttp(404, {"error": {"code": "NotFoundError"}}), TIStatus.NOT_LISTED),
    ],
)
def test_virustotal_verdicts(http, status):
    assert VirusTotalProvider(KEY, http=http).check_url(URL, "").status == status


def test_virustotal_is_lookup_only():
    http = vt(0)
    result = VirusTotalProvider(KEY, http=http).check_url(URL, "")
    request = http.requests[0]
    assert request["method"] == "GET" and request["body"] == b""  # never a submission
    assert request["url"] == "https://www.virustotal.com/api/v3/urls/" + url_id(URL)
    assert request["headers"]["x-apikey"] == KEY
    assert result.detail == "0/60 engines"


def test_virustotal_respects_the_public_quota():
    now = [0.0]
    provider = VirusTotalProvider(KEY, http=vt(0), max_per_minute=2, clock=lambda: now[0])
    assert provider.check_url(URL, "").status == TIStatus.NOT_LISTED
    assert provider.check_url(URL, "").status == TIStatus.NOT_LISTED
    third = provider.check_url(URL, "")
    assert (third.status, third.detail) == (TIStatus.UNAVAILABLE, "quota")
    now[0] = 61
    assert provider.check_url(URL, "").status == TIStatus.NOT_LISTED


# --- PhishTank ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("results", "status"),
    [
        ({"in_database": True, "valid": True, "verified": True}, TIStatus.LISTED),
        ({"in_database": True, "valid": False, "verified": False}, TIStatus.PARTIAL),
        ({"in_database": False}, TIStatus.NOT_LISTED),
    ],
)
def test_phishtank(results, status):
    http = FakeHttp(200, {"results": results})
    assert PhishTankProvider(KEY, http=http).check_url(URL, "").status == status


# --- real HTTP client (no network: a failing pool) ----------------------------------------------
def test_http_client_errors_never_carry_the_request_text(monkeypatch):
    client = Urllib3Client()

    def boom(*args, **kwargs):
        raise urllib3.exceptions.MaxRetryError(None, f"https://api.test/?key={KEY}", "down")

    monkeypatch.setattr(client._pool, "request", boom)
    with pytest.raises(TIHttpError) as info:
        client.request("GET", f"https://api.test/?key={KEY}", timeout=1)
    assert KEY not in str(info.value) and info.value.__cause__ is None
    assert info.value.__suppress_context__


class _Body:
    def __init__(self, status, data):
        self.status, self._data = status, data

    def read(self, amount):
        return self._data[:amount]

    def release_conn(self):
        pass


@pytest.mark.parametrize(
    ("raw", "expected"), [(b'{"a": 1}', {"a": 1}), (b"", None), (b"<html>", None)]
)
def test_http_client_parses_json_or_returns_none(monkeypatch, raw, expected):
    client = Urllib3Client()
    monkeypatch.setattr(client._pool, "request", lambda *a, **k: _Body(200, raw))
    assert client.request("GET", "https://api.test/", timeout=1).data == expected


def test_http_client_rejects_huge_responses(monkeypatch):
    client = Urllib3Client()
    monkeypatch.setattr("app.threat_intelligence.http.MAX_RESPONSE_BYTES", 4)
    monkeypatch.setattr(client._pool, "request", lambda *a, **k: _Body(200, b"0123456789"))
    with pytest.raises(TIHttpError):
        client.request("GET", "https://api.test/", timeout=1)
