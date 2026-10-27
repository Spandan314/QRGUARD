"""Threat intelligence inside the existing URL -> risk-engine pipeline (all APIs faked)."""

import logging

import pytest

from app.config import Config, ConfigError
from app.threat_intelligence import feeds
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.service import ThreatIntelService
from tests.conftest import make_app
from tests.fakes import FakeFetcher, FakeHttp, FakeProvider, FakeResolver

KEYS = {
    "URLHAUS_AUTH_KEY": "urlhaus-SECRET-key-111",
    "GOOGLE_SAFE_BROWSING_API_KEY": "gsb-SECRET-key-222",
    "VIRUSTOTAL_API_KEY": "vt-SECRET-key-333",
    "PHISHTANK_API_KEY": "pt-SECRET-key-444",
}
DEMO_LISTED = "http://secure-sbi-kyc-update.example/login"


def offline(app):
    service = app.extensions["qrguard.url_analysis"]
    service.resolver = FakeResolver()
    service.fetcher = FakeFetcher()
    return service


def analyze(client, url):
    response = client.post("/api/analyze/url", json={"url": url})
    assert response.status_code == 200
    return response.get_json()


def with_providers(*providers):
    app = make_app()
    offline(app).threat_intel = ThreatIntelService(list(providers))
    return app.test_client()


# --- default configuration: local feeds on, external providers off ------------------------------
def test_default_config_uses_local_feed_and_reports_disabled_external_providers():
    app = make_app()
    offline(app)
    body = analyze(app.test_client(), "https://www.wikipedia.org/")
    providers = {p["provider"]: p for p in body["threat_intel"]["providers"]}
    assert providers["local_feed"] == {
        "provider": "local_feed",
        "status": "not_listed",
        "limited_coverage": True,
    }
    for name in ("urlhaus", "google_safe_browsing", "virustotal", "phishtank"):
        assert providers[name]["status"] == "disabled"
    assert body["threat_intel"]["checked"] is True
    assert "demo blocklist" in body["threat_intel"]["note"]


def test_demo_blocklist_hit_scores_but_is_never_called_verified_threat_intelligence():
    app = make_app()
    offline(app)
    body = analyze(app.test_client(), DEMO_LISTED)
    assert body["risk_score"] == 90 and body["risk_level"] == "MALICIOUS"  # the demo still works
    assert body["verification"]["status"] == "UNVERIFIED"
    assert body["verification"]["source"] is None
    assert "demo blocklist" in body["verification"]["message"]
    assert body["verdict"]["confirmed"] is False and body["verdict"]["evidence"] == "demo_blocklist"
    ids = [i["id"] for i in body["indicators"]]
    assert "TI_DEMO_LISTED" in ids and "TI_LISTED" not in ids
    assert body["score_breakdown"]["floor_applied"]["indicator"] == "TI_DEMO_LISTED"


def test_a_demo_listing_alone_never_gives_high_confidence():
    from app.threat_intelligence.base import ProviderResult, ThreatIntelProvider

    class DemoList(ThreatIntelProvider):
        name = "local_feed"

        def check_url(self, normalized_url, domain):
            return ProviderResult(self.name, TIStatus.LISTED, "blocklist", limited=True)

    app = make_app()
    offline(app).threat_intel = ThreatIntelService([DemoList()])
    body = analyze(app.test_client(), "https://unknown-shop.in/")  # no warning signs of its own
    assert body["risk_level"] == "MALICIOUS" and body["confidence"] != "HIGH"
    assert body["verdict"]["evidence"] == "demo_blocklist"


def test_a_real_provider_listing_is_confirmed_threat_intelligence():
    app = make_app()
    offline(app)
    app.extensions["qrguard.url_analysis"].threat_intel = ThreatIntelService(
        [FakeProvider("urlhaus", TIStatus.LISTED, "malware_download")]
    )
    body = analyze(app.test_client(), "https://unknown-shop.in/file")
    assert body["risk_level"] == "MALICIOUS" and body["confidence"] == "HIGH"
    assert body["verification"]["source"] == "threat_intelligence"
    assert (
        body["verdict"]["confirmed"] is True
        and body["verdict"]["evidence"] == "threat_intelligence"
    )


def test_demo_blocklist_hit_in_a_message_and_a_qr_code():
    app = make_app()
    offline(app)
    client = app.test_client()
    message = client.post(
        "/api/analyze/message", json={"text": f"Hi, see the photos here: {DEMO_LISTED}"}
    ).get_json()
    assert (
        message["risk_level"] == "MALICIOUS" and message["verification"]["status"] == "UNVERIFIED"
    )
    qr = client.post("/api/analyze/qr", json={"content": DEMO_LISTED}).get_json()
    assert qr["risk_score"] == 90 and qr["verdict"]["evidence"] == "demo_blocklist"


def test_demo_only_not_listed_does_not_raise_confidence():
    app = make_app()
    offline(app)
    body = analyze(app.test_client(), "https://unknown-shop.in/")
    assert body["risk_level"] == "SAFE" and body["confidence"] == "LOW"


# --- score integration ---------------------------------------------------------------------------
LOOKALIKE = "https://flipkrat.com/rewards"


def test_not_listed_never_lowers_the_score():
    baseline = analyze(with_providers(), LOOKALIKE)
    checked = analyze(
        with_providers(
            FakeProvider("urlhaus", TIStatus.NOT_LISTED),
            FakeProvider("google_safe_browsing", TIStatus.NOT_LISTED),
        ),
        LOOKALIKE,
    )
    assert checked["risk_score"] == baseline["risk_score"] == 60
    assert checked["risk_level"] == "MALICIOUS"
    assert checked["verification"]["status"] == "UNVERIFIED"


def test_unavailable_providers_fall_back_to_local_analysis():
    baseline = analyze(with_providers(), LOOKALIKE)
    body = analyze(
        with_providers(
            FakeProvider("urlhaus", TIStatus.UNAVAILABLE),
            FakeProvider("virustotal", TIStatus.ERROR),
        ),
        LOOKALIKE,
    )
    assert body["risk_score"] == baseline["risk_score"]
    assert body["indicators"] == baseline["indicators"]


def test_conflicting_results_one_listing_is_enough():
    body = analyze(
        with_providers(
            FakeProvider("urlhaus", TIStatus.NOT_LISTED),
            FakeProvider("google_safe_browsing", TIStatus.LISTED, "phishing"),
            FakeProvider("virustotal", TIStatus.PARTIAL, "suspicious"),
        ),
        "https://www.example.com/",
    )
    assert body["risk_score"] == 90 and body["risk_level"] == "MALICIOUS"
    assert "TI_LISTED" in [i["id"] for i in body["indicators"]]
    assert "TI_PARTIAL" not in [i["id"] for i in body["indicators"]]
    assert body["threat_intel"]["providers"][1] == {
        "provider": "google_safe_browsing",
        "status": "listed",
        "threat_type": "phishing",
    }


def test_partial_listing_adds_evidence_but_is_not_a_confirmation():
    body = analyze(
        with_providers(FakeProvider("virustotal", TIStatus.PARTIAL)), "https://www.example.com/"
    )
    assert "TI_PARTIAL" in [i["id"] for i in body["indicators"]]
    assert body["verification"]["status"] == "UNVERIFIED"
    assert body["risk_score"] > 0


def test_listed_overrides_a_trusted_domain():
    body = analyze(
        with_providers(FakeProvider("urlhaus", TIStatus.LISTED, "malware_download")),
        "https://www.wikipedia.org/",
    )
    assert body["risk_level"] == "MALICIOUS"
    assert body["verification"]["source"] == "threat_intelligence"


# --- external providers wired from the environment (HTTP faked) ---------------------------------
def keyed_app(http):
    app = make_app(**KEYS)
    offline(app)
    for provider in app.extensions["qrguard.url_analysis"].threat_intel.providers:
        if provider.external:
            provider._http = http
    return app


def test_keys_enable_providers_and_answers_flow_into_the_score():
    http = FakeHttp(200, {"query_status": "ok", "threat": "phishing"})  # every API "answers" this
    app = keyed_app(http)
    body = analyze(app.test_client(), "https://www.example.com/")
    statuses = {p["provider"]: p["status"] for p in body["threat_intel"]["providers"]}
    assert statuses["urlhaus"] == "listed"
    assert statuses["google_safe_browsing"] == "unavailable"  # unknown fields: malformed
    assert statuses["virustotal"] == "unavailable"  # malformed for VirusTotal
    assert body["risk_score"] == 90
    # only the URL is sent: no user text, no IP, no request id
    sent = b" ".join(r["body"] + r["url"].encode() for r in http.requests)
    assert b"www.example.com" in sent and b"request_id" not in sent


def test_second_lookup_is_served_from_the_cache():
    http = FakeHttp(200, {"query_status": "no_results"})
    client = keyed_app(http).test_client()
    analyze(client, "https://www.example.com/")
    first = len(http.requests)
    body = analyze(client, "https://www.example.com/")
    # URLhaus' "no_results" is cached; the providers that failed (malformed answer) ask again
    assert len(http.requests) - first == first - 1
    assert body["threat_intel"]["providers"][1] == {
        "provider": "urlhaus",
        "status": "not_listed",
        "cached": True,
    }
    assert any(p.get("cached") for p in body["threat_intel"]["providers"])


def test_api_keys_never_appear_in_responses_logs_or_health(caplog):
    caplog.set_level(logging.DEBUG)
    http = FakeHttp(401, {"error": "bad key"})
    app = keyed_app(http)
    client = app.test_client()
    body = analyze(client, "https://www.example.com/")
    assert {p["status"] for p in body["threat_intel"]["providers"][1:]} == {"error"}
    health = client.get("/api/health").get_data(as_text=True)
    everything = str(body) + health + caplog.text + repr(app.config["QRGUARD"])
    for secret in KEYS.values():
        assert secret not in everything
    assert "www.example.com" not in caplog.text


def test_health_lists_providers_without_secrets():
    body = make_app(URLHAUS_AUTH_KEY=KEYS["URLHAUS_AUTH_KEY"]).test_client().get("/api/health")
    ti = body.get_json()["components"]["threat_intel"]
    assert ti["enabled"] is True
    assert {"provider": "urlhaus", "enabled": True, "external": True} in ti["providers"]
    assert {"provider": "virustotal", "enabled": False, "external": True} in ti["providers"]
    assert {"provider": "local_feed", "enabled": True, "external": False} in ti["providers"]


# --- configuration ------------------------------------------------------------------------------
def test_feed_dir_is_loaded_at_startup(tmp_path):
    (tmp_path / "openphish.txt").write_text("http://feed-listed.test/phish\n")
    app = make_app(THREAT_INTEL_FEED_DIR=str(tmp_path))
    offline(app)
    body = analyze(app.test_client(), "http://feed-listed.test/phish")
    local = body["threat_intel"]["providers"][0]
    assert local == {"provider": "local_feed", "status": "listed", "threat_type": "blocklist"}
    assert body["risk_score"] == 90


def test_missing_feed_dir_is_not_fatal(tmp_path):
    app = make_app(THREAT_INTEL_FEED_DIR=str(tmp_path / "nope"))
    offline(app)
    assert analyze(app.test_client(), "https://www.example.com/")["risk_level"] == "SAFE"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"THREAT_INTEL_LOCAL_FEEDS_ENABLED": "maybe"}, "true or false"),
        ({"THREAT_INTEL_TIMEOUT_SECONDS": "99"}, "between"),
        ({"VIRUSTOTAL_API_KEY": "bad key with spaces!"}, "value not shown"),
    ],
)
def test_invalid_ti_settings_fail_at_startup_without_echoing_secrets(env, message):
    with pytest.raises(ConfigError) as info:
        Config.from_env(env)
    assert message in str(info.value)
    assert "bad key" not in str(info.value)


def test_ti_boolean_setting_values():
    assert Config.from_env({"THREAT_INTEL_LOCAL_FEEDS_ENABLED": "off"}).ti_local_feeds_enabled is (
        False
    )
    assert Config.from_env({"THREAT_INTEL_LOCAL_FEEDS_ENABLED": "1"}).ti_local_feeds_enabled


# --- feed download command (network faked) -----------------------------------------------------
class _Response:
    def __init__(self, status, data):
        self.status, self._data = status, data

    def read(self, amount):
        return self._data[:amount]

    def release_conn(self):
        pass


def test_update_feeds_requires_a_directory():
    result = make_app().test_cli_runner().invoke(args=["ti-update-feeds"])
    assert result.exit_code != 0 and "THREAT_INTEL_FEED_DIR" in result.output


def test_update_feeds_downloads_and_keeps_old_file_on_failure(tmp_path, monkeypatch):
    (tmp_path / "urlhaus_recent.txt").write_text("old.test\n")

    def fake_request(self, method, url, **kwargs):
        if "openphish" in url:
            return _Response(200, b"# header\nhttp://a.test/x\nhttp://b.test/y\n")
        return _Response(503, b"")

    monkeypatch.setattr("urllib3.PoolManager.request", fake_request)
    runner = make_app(THREAT_INTEL_FEED_DIR=str(tmp_path)).test_cli_runner()
    result = runner.invoke(args=["ti-update-feeds"])
    assert result.exit_code == 0
    assert "openphish.txt: 2 entries" in result.output
    assert "urlhaus_recent.txt: not updated (urlhaus_recent.txt: HTTP 503)" in result.output
    assert (tmp_path / "urlhaus_recent.txt").read_text() == "old.test\n"
    assert not list(tmp_path.glob("*.part"))


def test_update_feeds_fails_when_nothing_downloads(tmp_path, monkeypatch):
    import urllib3

    def fail(self, *args, **kwargs):
        raise urllib3.exceptions.NewConnectionError(None, "no network")

    monkeypatch.setattr("urllib3.PoolManager.request", fail)
    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 10)
    result = (
        make_app(THREAT_INTEL_FEED_DIR=str(tmp_path))
        .test_cli_runner()
        .invoke(args=["ti-update-feeds"])
    )
    assert result.exit_code != 0 and "network error" in result.output


def test_oversized_feed_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "MAX_FEED_BYTES", 5)
    monkeypatch.setattr(
        "urllib3.PoolManager.request", lambda self, *a, **k: _Response(200, b"0123456789")
    )
    result = (
        make_app(THREAT_INTEL_FEED_DIR=str(tmp_path))
        .test_cli_runner()
        .invoke(args=["ti-update-feeds"])
    )
    assert result.exit_code != 0 and "larger than" in result.output
    assert not list(tmp_path.iterdir())


# --- regression: malformed IPv6 links (found while testing feed parsing) ----------------------
@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/api/analyze/url", {"url": "http://[::1"}),
        ("/api/analyze/message", {"text": "Verify your account now: http://[::1/login"}),
        ("/api/analyze/qr", {"content": "https://[bad]/"}),
    ],
)
def test_malformed_ipv6_links_never_cause_a_server_error(path, payload):
    app = make_app()
    offline(app)
    response = app.test_client().post(path, json=payload)
    assert response.status_code in (200, 400)
    assert response.get_json().get("error", {}).get("code") != "INTERNAL_ERROR"


def test_urlhaus_rejecting_the_key_is_reported_precisely_and_never_safe():
    # The real provider class, with URLhaus' documented answer to an unknown Auth-Key.
    from app.threat_intelligence.providers.urlhaus import UrlhausProvider
    from tests.fakes import FakeHttp

    answer = {"query_status": "unknown_auth_key"}
    rejected = UrlhausProvider("urlhaus-test-key-0001", http=FakeHttp(200, answer))
    for url in ("https://www.wikipedia.org/", "https://unknown-shop.in/"):  # trusted and unknown
        body = analyze(with_providers(rejected), url)
        rows = {p["provider"]: p for p in body["threat_intel"]["providers"]}
        assert rows["urlhaus"]["status"] == "error"
        assert rows["urlhaus"]["detail"] == "auth key rejected"
        check = next(c for c in body["checks"] if c["id"] == "threat_intelligence")
        assert check["status"] == "unavailable"
        assert "URLhaus (auth key rejected)" in check["detail"]
        assert body["confidence"] == "LOW"
        assert body["verdict"]["evidence"] != "threat_intelligence"  # never "verified by URLhaus"
        assert "urlhaus-test-key-0001" not in str(body)
    # An unknown site stays UNVERIFIED; only the curated trusted list (row above) may say SAFE.
    assert (
        body["verdict"]["label"] == "UNVERIFIED" and body["verdict"]["evidence"] == "insufficient"
    )
