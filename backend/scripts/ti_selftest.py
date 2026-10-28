"""Live check of the configured threat-intelligence providers. Prints NO key values.

    cd backend
    read -rs GOOGLE_SAFE_BROWSING_API_KEY && export GOOGLE_SAFE_BROWSING_API_KEY   # etc.
    python -m scripts.ti_selftest

A provider counts as WORKING only when it really answered:
  * every configured provider must give a definitive answer (listed / not listed) for a harmless
    address (https://www.example.com/);
  * Google Safe Browsing must also LIST Google's official test phishing page, which proves that
    real lookups (not just authentication) work. The other providers publish no permanent
    test-threat URL, so for them only the harmless lookup is checked.
Each provider gets one label:
  WORKING         it answered (and, for Safe Browsing, listed the official test threat);
  FAILED          it answered with an error, e.g. a rejected key, or answered wrongly;
  RATE LIMITED    it refused for now because of a rate limit or quota (not a key problem);
  NOT VERIFIED    no usable answer: timeout, network error, provider outage, an unreadable
                  response or an unexpected error (never printed: it could contain the key).
                  This says nothing about the key; try again later or elsewhere;
  NOT CONFIGURED  no key (or PhishTank anonymous mode) is set.
Exit code: 0 = every configured provider works, 1 = at least one FAILED, 2 = none configured,
3 = none failed but at least one is RATE LIMITED or NOT VERIFIED.
Nothing is saved; the API keys are read from the environment and never printed.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass

from app.config import Config
from app.threat_intelligence.base import DEFINITIVE_STATUSES, ThreatIntelProvider, TIStatus
from app.threat_intelligence.providers.phishtank import PhishTankProvider
from app.threat_intelligence.providers.safe_browsing import SafeBrowsingProvider
from app.threat_intelligence.providers.urlhaus import UrlhausProvider
from app.threat_intelligence.providers.virustotal import VirusTotalProvider

CLEAN_URL = "https://www.example.com/"
# Google's official Safe Browsing test page (listed as SOCIAL_ENGINEERING by design).
GSB_TEST_PHISHING = "https://testsafebrowsing.appspot.com/s/phishing.html"
KNOWN_THREATS = {"google_safe_browsing": GSB_TEST_PHISHING}
ENV_NAMES = {
    "google_safe_browsing": "GOOGLE_SAFE_BROWSING_API_KEY",
    "urlhaus": "URLHAUS_AUTH_KEY",
    "phishtank": "PHISHTANK_API_KEY (or PHISHTANK_ANONYMOUS=true)",
    "virustotal": "VIRUSTOTAL_API_KEY",
}


WORKING = "WORKING"
FAILED = "FAILED"
RATE_LIMITED = "RATE LIMITED"
NOT_VERIFIED = "NOT VERIFIED"
NOT_CONFIGURED = "NOT CONFIGURED"
RATE_LIMIT_DETAILS = {"rate limited", "quota"}


@dataclass
class Outcome:
    provider: str
    configured: bool
    working: bool
    detail: str
    label: str = ""


def build_providers(env: Mapping[str, str]) -> list[ThreatIntelProvider]:
    config = Config.from_env({**env, "APP_ENV": "development"})
    timeout = max(config.ti_timeout_seconds, 5)  # a one-off check may wait a little longer
    return [
        SafeBrowsingProvider(config.google_safe_browsing_api_key, timeout=timeout),
        UrlhausProvider(config.urlhaus_auth_key, timeout=timeout),
        PhishTankProvider(
            config.phishtank_api_key, timeout=timeout, anonymous=config.phishtank_anonymous
        ),
        VirusTotalProvider(config.virustotal_api_key, timeout=timeout),
    ]


def _describe(status: TIStatus, detail: str | None) -> str:
    return status.value + (f" ({detail})" if detail else "")


def _failure_label(status: TIStatus, detail: str | None) -> str:
    """Why a lookup gave no answer. Only an ERROR (e.g. a rejected key) counts as FAILED."""
    if status == TIStatus.ERROR:
        return FAILED
    if status == TIStatus.UNAVAILABLE and detail in RATE_LIMIT_DETAILS:
        return RATE_LIMITED
    return NOT_VERIFIED  # timeout, network error, provider error, unexpected response


def check(provider: ThreatIntelProvider) -> Outcome:
    if not provider.is_enabled():
        return Outcome(
            provider.name,
            False,
            False,
            f"not configured: set {ENV_NAMES[provider.name]}",
            NOT_CONFIGURED,
        )
    clean = provider.check_url(CLEAN_URL, "example.com")
    note = "harmless lookup: " + _describe(clean.status, clean.detail)
    if clean.status not in DEFINITIVE_STATUSES:
        return Outcome(provider.name, True, False, note, _failure_label(clean.status, clean.detail))
    notes = [note]
    threat_url = KNOWN_THREATS.get(provider.name)
    if threat_url:
        threat = provider.check_url(threat_url, "testsafebrowsing.appspot.com")
        notes.append("official test threat: " + _describe(threat.status, threat.detail))
        if threat.status not in DEFINITIVE_STATUSES:
            label = _failure_label(threat.status, threat.detail)
            return Outcome(provider.name, True, False, "; ".join(notes), label)
        if threat.status != TIStatus.LISTED:  # answered, but missed the official test threat
            return Outcome(provider.name, True, False, "; ".join(notes), FAILED)
    else:
        notes.append("no official test-threat URL (only the harmless lookup was checked)")
    return Outcome(provider.name, True, True, "; ".join(notes), WORKING)


def _safe_check(provider: ThreatIntelProvider) -> Outcome:
    """check() for one provider; an unexpected exception never stops the others.

    Nothing about the exception is printed or logged: its message or traceback could contain
    the request URL, and Safe Browsing sends its key in the URL.
    """
    try:
        return check(provider)
    except Exception:  # deliberately broad, see above
        return Outcome(provider.name, True, False, "unexpected error", NOT_VERIFIED)


def run(providers: list[ThreatIntelProvider]) -> tuple[int, list[Outcome]]:
    outcomes = [_safe_check(p) for p in providers]
    configured = [o for o in outcomes if o.configured]
    if not configured:
        return 2, outcomes
    if any(o.label == FAILED for o in configured):
        return 1, outcomes
    return (0 if all(o.working for o in configured) else 3), outcomes


def main() -> int:
    code, outcomes = run(build_providers(os.environ))
    for o in outcomes:
        print(f"{o.label:14}  {o.provider:22} {o.detail}")
    if code == 2:
        print("\nNo provider is configured. See docs/deployment.md §2a for the keys.")
    elif code == 1:
        print("\nA provider FAILED (e.g. its key was rejected): do not enable it on Render yet.")
    elif code == 3:
        print(
            "\nNo provider failed, but some could not be verified (rate limit, quota, timeout,"
            " network or provider problem). Try again later; this does not prove a key is wrong."
        )
    else:
        print("\nAll configured providers answered correctly.")
    return code


if __name__ == "__main__":
    sys.exit(main())
