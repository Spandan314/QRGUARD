"""Provider configuration: VirusTotal per-process pacing and PhishTank anonymous mode, from the
environment through Config and the factory to the provider (fake HTTP, no network)."""

from pathlib import Path

import pytest
import yaml

from app.analyzers.url_rules import load_url_rules
from app.config import Config, ConfigError
from app.threat_intelligence.base import TIStatus
from app.threat_intelligence.factory import build_threat_intel
from tests.fakes import FakeHttp

URL = "https://example.com/"
VT_KEY = "vt-test-key-not-real"
PT_KEY = "pt-test-key-not-real"
RENDER_YAML = Path(__file__).resolve().parents[3] / "render.yaml"


def provider(env: dict[str, str], name: str):
    config = Config.from_env({"APP_ENV": "development", **env})
    service = build_threat_intel(config, load_url_rules())
    return next(p for p in service.providers if p.name == name)


def vt_clean():
    stats = {"malicious": 0, "suspicious": 0, "harmless": 60}
    return FakeHttp(200, {"data": {"attributes": {"last_analysis_stats": stats}}})


# --- VirusTotal: per-process limit ------------------------------------------------------------
def test_virustotal_default_limit_keeps_two_workers_within_the_public_quota():
    assert Config.from_env({}).virustotal_max_per_minute == 2
    workers = [provider({"VIRUSTOTAL_API_KEY": VT_KEY}, "virustotal") for _ in range(2)]
    assert all(w.max_per_minute == 2 for w in workers)
    now = [0.0]
    for w in workers:
        w._http, w._clock = vt_clean(), (lambda: now[0])
    # Two Gunicorn workers each look up as fast as they can within one minute.
    answered = sum(
        w.check_url(URL, "example.com").status == TIStatus.NOT_LISTED
        for _ in range(5)
        for w in workers
    )
    assert answered == 4  # never more than the free API's ~4 lookups/min in total
    assert sum(len(w._http.requests) for w in workers) == 4


def test_virustotal_configured_limit_is_used_and_the_window_slides():
    vt = provider({"VIRUSTOTAL_API_KEY": VT_KEY, "VIRUSTOTAL_MAX_PER_MINUTE": "3"}, "virustotal")
    assert vt.max_per_minute == 3
    now = [0.0]
    vt._http, vt._clock = vt_clean(), (lambda: now[0])
    assert [vt.check_url(URL, "").status for _ in range(3)] == [TIStatus.NOT_LISTED] * 3
    over = vt.check_url(URL, "")
    assert (over.status, over.detail) == (TIStatus.UNAVAILABLE, "quota")  # skipped, never clean
    assert len(vt._http.requests) == 3  # the skipped lookup was not sent
    now[0] = 60.5
    assert vt.check_url(URL, "").status == TIStatus.NOT_LISTED


@pytest.mark.parametrize("value", ["0", "-1", "61", "abc", "2.5"])
def test_virustotal_invalid_limit_fails_at_startup(value):
    with pytest.raises(ConfigError, match="VIRUSTOTAL_MAX_PER_MINUTE"):
        Config.from_env({"VIRUSTOTAL_MAX_PER_MINUTE": value})


def test_virustotal_without_a_key_stays_disabled_whatever_the_limit():
    vt = provider({"VIRUSTOTAL_MAX_PER_MINUTE": "4"}, "virustotal")
    assert not vt.is_enabled() and vt.check_url(URL, "").status == TIStatus.DISABLED


# --- PhishTank: anonymous mode and key mode ---------------------------------------------------
def phishtank_answer():
    return FakeHttp(200, {"results": {"url": URL, "in_database": False}})


def test_phishtank_unset_is_off_without_a_key():
    pt = provider({}, "phishtank")
    assert Config.from_env({}).phishtank_anonymous is False
    assert not pt.is_enabled() and pt.check_url(URL, "").status == TIStatus.DISABLED


def test_phishtank_anonymous_mode_sends_no_key():
    pt = provider({"PHISHTANK_ANONYMOUS": "true"}, "phishtank")
    pt._http = phishtank_answer()
    assert pt.is_enabled() and pt.check_url(URL, "").status == TIStatus.NOT_LISTED
    assert b"app_key" not in pt._http.requests[0]["body"]


def test_phishtank_key_mode_sends_the_key_and_wins_over_anonymous():
    for env in (
        {"PHISHTANK_API_KEY": PT_KEY},
        {"PHISHTANK_API_KEY": PT_KEY, "PHISHTANK_ANONYMOUS": "true"},
    ):
        pt = provider(env, "phishtank")
        pt._http = phishtank_answer()
        assert pt.check_url(URL, "").status == TIStatus.NOT_LISTED
        assert b"app_key=" + PT_KEY.encode() in pt._http.requests[0]["body"]


@pytest.mark.parametrize(("value", "expected"), [("false", False), ("0", False), ("TRUE", True)])
def test_phishtank_anonymous_values(value, expected):
    assert Config.from_env({"PHISHTANK_ANONYMOUS": value}).phishtank_anonymous is expected


def test_phishtank_anonymous_invalid_value_fails_at_startup():
    with pytest.raises(ConfigError, match="PHISHTANK_ANONYMOUS"):
        Config.from_env({"PHISHTANK_ANONYMOUS": "maybe"})


# --- render.yaml ------------------------------------------------------------------------------
def test_render_yaml_defaults_are_safe():
    service = yaml.safe_load(RENDER_YAML.read_text())["services"][0]
    env = {e["key"]: e for e in service["envVars"]}
    assert env["PHISHTANK_ANONYMOUS"]["value"] == "false"
    per_process = int(env["VIRUSTOTAL_MAX_PER_MINUTE"]["value"])
    assert per_process * int(env["WEB_CONCURRENCY"]["value"]) <= 4
    assert env["REDIRECT_RESOLUTION"]["value"] == "shorteners_only"
    for key in (
        "URLHAUS_AUTH_KEY",
        "GOOGLE_SAFE_BROWSING_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "PHISHTANK_API_KEY",
    ):
        assert env[key] == {"key": key, "sync": False}  # secrets never have a value here
