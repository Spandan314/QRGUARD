"""URL analysis pipeline: normalise -> features -> lookalike -> redirects -> threat intel -> score.

This service is used by ``POST /api/analyze/url`` now, and later by the QR, message and
screenshot analyzers whenever they find a link.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.analyzers import redirect_resolver as rr
from app.analyzers.lookalike import BrandMatch, detect_lookalikes
from app.analyzers.url_features import extract_url_features, host_matches, is_local_host
from app.analyzers.url_normalizer import ParsedURL, URLValidationError, normalize_url
from app.analyzers.url_rules import UrlRules
from app.scoring.engine import ScoreResult, ScoringContext, score_indicators
from app.scoring.indicator import Indicator
from app.scoring.recommendations import DISCLAIMER, recommendation_for, summary_for
from app.scoring.settings import ScoringSettings
from app.threat_intelligence.base import DEFINITIVE_STATUSES, ProviderResult, TIStatus
from app.threat_intelligence.service import ThreatIntelService
from app.utils.net_safety import resolve_host

REDIRECT_MODES = ("off", "shorteners_only", "all")
PROVIDER_NAMES = {
    "local_feed": "local blocklist",
    "urlhaus": "URLhaus",
    "google_safe_browsing": "Google Safe Browsing",
    "virustotal": "VirusTotal",
    "phishtank": "PhishTank",
}
FAILED_STATUSES = {TIStatus.UNAVAILABLE, TIStatus.ERROR}
INCOMPLETE_STATUSES = {
    rr.TIMEOUT,
    rr.CONNECTION_ERROR,
    rr.TLS_ERROR,
    rr.INVALID_REDIRECT,
    rr.CAPACITY_EXHAUSTED,
}


@dataclass
class UrlAnalysis:
    """Everything learned about one URL (used by other analyzers too)."""

    parsed: ParsedURL
    features: dict[str, Any] = field(default_factory=dict)
    brand: BrandMatch | None = None
    indicators: list[Indicator] = field(default_factory=list)
    redirects: dict[str, Any] = field(default_factory=dict)
    ti_results: list[ProviderResult] = field(default_factory=list)
    incomplete_checks: bool = False


def _combine(url_indicators: list[Indicator], brand_indicators: list[Indicator]) -> list[Indicator]:
    """URL and brand indicators together, each piece of evidence counted once. The generic
    domain-name signs are for brandless scam domains: when a brand check already describes the
    domain ("sbi-kyc-verify.top", "sbi.co.in.kyc.xyz"), they would repeat the same evidence."""
    if brand_indicators:
        url_indicators = [i for i in url_indicators if i.id != "URL_KEYWORDS_IN_DOMAIN"]
    if any(i.id == "OFFICIAL_DOMAIN_IN_SUBDOMAIN" for i in brand_indicators):
        url_indicators = [i for i in url_indicators if i.id != "URL_DOMAIN_IN_SUBDOMAIN"]
    return [*url_indicators, *brand_indicators]


class UrlAnalysisService:
    def __init__(
        self,
        rules: UrlRules,
        scoring: ScoringSettings,
        threat_intel: ThreatIntelService,
        redirect_mode: str = "shorteners_only",
        redirect_settings: rr.RedirectSettings | None = None,
        fetcher: rr.Fetcher = rr.urllib3_fetch,
        resolver: rr.Resolver = resolve_host,
    ) -> None:
        if redirect_mode not in REDIRECT_MODES:
            raise ValueError(f"redirect_mode must be one of {REDIRECT_MODES}")
        self.rules = rules
        self.scoring = scoring
        self.threat_intel = threat_intel
        self.redirect_mode = redirect_mode
        self.redirect_settings = redirect_settings or rr.RedirectSettings()
        # Shared by every request thread of this worker process.
        self.redirect_slots = rr.RedirectSlots(
            self.redirect_settings.max_concurrent, self.redirect_settings.slot_wait
        )
        # Network functions are attributes so tests can replace them with fakes.
        self.fetcher = fetcher
        self.resolver = resolver

    # ----- public API ---------------------------------------------------------------------------
    def analyze(self, raw_url: str) -> dict[str, Any]:
        """Analyse one URL and return the API response body (without request_id)."""
        analysis, result = self.analyze_link(raw_url)
        return self._response(analysis, result)

    def analyze_link(
        self, raw_url: str, resolve_redirects: bool = True
    ) -> tuple[UrlAnalysis, ScoreResult]:
        """Analyse and score one link on its own (also used for links inside messages)."""
        analysis = self.collect(raw_url, resolve_redirects=resolve_redirects)
        result = score_indicators(
            self.scoring,
            analysis.indicators,
            applicable_modules={"url_qr"},
            ti_results=analysis.ti_results,
            context=ScoringContext(incomplete_checks=analysis.incomplete_checks),
        )
        return analysis, result

    def collect(self, raw_url: str, resolve_redirects: bool = True) -> UrlAnalysis:
        """Run every URL check and gather indicators (no scoring). Raises URLValidationError."""
        parsed = normalize_url(raw_url, self.rules)
        if parsed.is_dangerous_scheme:
            return UrlAnalysis(
                parsed=parsed,
                indicators=[Indicator("URL_DANGEROUS_SCHEME", f"{parsed.scheme}:")],
                redirects={"checked": False, "status": rr.NOT_ATTEMPTED},
            )

        features, indicators = extract_url_features(parsed, self.rules)
        brand, brand_indicators = detect_lookalikes(parsed, self.rules)
        analysis = UrlAnalysis(parsed, features, brand, _combine(indicators, brand_indicators))

        if resolve_redirects:
            self._check_redirects(analysis)
        else:
            analysis.redirects = {
                "checked": False,
                "status": rr.NOT_ATTEMPTED,
                "reason": "redirect-check limit for this request reached",
            }
        urls_to_check = [parsed.normalized]
        final_url = analysis.redirects.get("final_url")
        if final_url and final_url != parsed.normalized:
            urls_to_check.append(final_url)
        for url in urls_to_check:
            analysis.ti_results.extend(self.threat_intel.check(url, parsed.registrable_domain))
        # An enabled provider that timed out, was rate limited or rejected its key gave NO answer:
        # that is an incomplete check (lower confidence), never a clean result.
        if any(r.status in FAILED_STATUSES and not r.limited for r in analysis.ti_results):
            analysis.incomplete_checks = True
        return analysis

    # ----- redirects ----------------------------------------------------------------------------
    def _should_resolve(self, parsed: ParsedURL, features: dict[str, Any]) -> tuple[bool, str]:
        if self.redirect_mode == "off":
            return False, "disabled"
        if is_local_host(parsed, self.rules):
            return False, "private address (never contacted)"
        if parsed.port is not None:
            return False, "non-standard port (never contacted)"
        if self.redirect_mode == "shorteners_only" and not features.get("is_shortener"):
            return False, "only shortened links are followed"
        return True, ""

    def _check_redirects(self, analysis: UrlAnalysis) -> None:
        parsed = analysis.parsed
        should, reason = self._should_resolve(parsed, analysis.features)
        if not should:
            analysis.redirects = {"checked": False, "status": rr.NOT_ATTEMPTED, "reason": reason}
            return

        result = rr.resolve_redirects(
            parsed.normalized,
            settings=self.redirect_settings,
            dangerous_schemes=self.rules.dangerous_schemes,
            local_host_suffixes=self.rules.local_host_suffixes,
            fetcher=self.fetcher,
            resolver=self.resolver,
            slots=self.redirect_slots,
        )
        analysis.redirects = {
            "checked": True,
            "status": result.status,
            "redirect_count": result.redirect_count,
            "hops": [hop.to_dict() for hop in result.hops],
            "final_url": result.final_url,
        }
        on_redirect = bool(result.hops)  # False: the problem was with the link itself
        add = analysis.indicators.append

        if result.status == rr.COMPLETED:
            self._analyze_destination(analysis, result)
        elif result.status == rr.TOO_MANY_REDIRECTS:
            add(
                Indicator("REDIRECT_CHAIN_TOO_LONG", f"more than {self.redirect_settings.max_hops}")
            )
        elif result.status == rr.BLOCKED_PRIVATE_ADDRESS:
            add(
                Indicator("REDIRECT_TO_PRIVATE_ADDRESS", "blocked")
                if on_redirect
                else Indicator("URL_PRIVATE_NETWORK_HOST", "domain resolves to a private address")
            )
        elif result.status == rr.BLOCKED_DANGEROUS_SCHEME:
            scheme = (result.blocked_url or "").split(":", 1)[0]
            add(Indicator("REDIRECT_DANGEROUS_SCHEME", f"{scheme}:"))
        elif result.status == rr.BLOCKED_SCHEME:
            scheme = (result.blocked_url or "").split(":", 1)[0]
            add(Indicator("REDIRECT_NON_WEB_SCHEME", f"{scheme}:"))
        elif result.status == rr.BLOCKED_PORT:
            add(Indicator("REDIRECT_BLOCKED_PORT"))
        elif result.status == rr.DNS_FAILURE:
            add(Indicator("DOMAIN_NOT_RESOLVING"))
            analysis.incomplete_checks = True
        elif result.status in INCOMPLETE_STATUSES:
            add(Indicator("REDIRECT_CHECK_INCOMPLETE", result.status.replace("_", " ")))
            analysis.incomplete_checks = True

        schemes = [hop.url.split(":", 1)[0].lower() for hop in result.hops]
        if result.final_url:
            schemes.append(result.final_url.split(":", 1)[0].lower())
        if any(a == "https" and b == "http" for a, b in zip(schemes, schemes[1:], strict=False)):
            add(Indicator("REDIRECT_HTTPS_DOWNGRADE"))

    def _analyze_destination(self, analysis: UrlAnalysis, result: rr.RedirectResult) -> None:
        """If the link leads to another site, analyse that destination too."""
        if not result.final_url or result.final_url == analysis.parsed.normalized:
            return
        try:
            final = normalize_url(result.final_url, self.rules)
        except URLValidationError:
            analysis.indicators.append(
                Indicator("REDIRECT_CHECK_INCOMPLETE", "invalid destination")
            )
            return
        analysis.redirects["final_domain"] = final.registrable_domain
        if final.registrable_domain == analysis.parsed.registrable_domain:
            return

        analysis.indicators.append(Indicator("REDIRECT_CROSS_DOMAIN", final.registrable_domain))
        # Trust is judged on where the user actually ends up, not on the first hop.
        analysis.indicators = [i for i in analysis.indicators if i.id != "TRUSTED_DOMAIN"]
        _, final_indicators = extract_url_features(final, self.rules)
        final_brand, final_brand_indicators = detect_lookalikes(final, self.rules)
        present = {i.id for i in analysis.indicators}
        for indicator in _combine(final_indicators, final_brand_indicators):
            if indicator.id in ("URL_SCHEME_ASSUMED",):
                continue
            if indicator.id == "URL_SHORTENER" and host_matches(
                final.host, self.rules.url_shorteners
            ):
                continue
            if indicator.id not in present or indicator.id == "URL_PHISHING_KEYWORD":
                evidence = (
                    f"destination: {indicator.evidence}" if indicator.evidence else "destination"
                )
                analysis.indicators.append(Indicator(indicator.id, evidence))
                present.add(indicator.id)
        if final_brand is not None and analysis.brand is None:
            analysis.brand = final_brand

    # ----- checks performed (what the verdict is based on) ---------------------------------------
    REDIRECT_DETAIL = {
        rr.DNS_FAILURE: "the domain name does not resolve",
        rr.TIMEOUT: "the website did not answer in time",
        rr.CAPACITY_EXHAUSTED: "the link checker is busy; try again in a moment",
        rr.CONNECTION_ERROR: "the website could not be reached",
        rr.TLS_ERROR: "the website's HTTPS certificate could not be checked",
        rr.TOO_MANY_REDIRECTS: "too many redirects",
    }

    def _checks(self, analysis: UrlAnalysis) -> list[dict[str, Any]]:
        """Which checks ran, which could not, and why: the evidence behind the verdict."""
        checks = [
            {
                "id": "url_structure",
                "label": "Link structure and look-alike domains",
                "status": "completed",
                "detail": None,
            }
        ]
        redirects = analysis.redirects or {}
        status = redirects.get("status")
        if not redirects.get("checked"):
            checks.append(
                {
                    "id": "destination",
                    "label": "Where the link leads (redirects)",
                    "status": "not_run",
                    "detail": redirects.get("reason") or "not checked",
                }
            )
        elif status == rr.COMPLETED:
            final_domain = redirects.get("final_domain")
            if final_domain and final_domain != analysis.parsed.registrable_domain:
                detail = f"leads to another website: {final_domain}"
            elif redirects.get("redirect_count"):
                detail = f"{redirects['redirect_count']} redirect(s) on the same website"
            else:
                detail = "no redirect"
            checks.append(
                {
                    "id": "destination",
                    "label": "Where the link leads (redirects)",
                    "status": "completed",
                    "detail": detail,
                }
            )
        else:
            checks.append(
                {
                    "id": "destination",
                    "label": "Where the link leads (redirects)",
                    "status": "incomplete",
                    "detail": self.REDIRECT_DETAIL.get(status, str(status).replace("_", " ")),
                }
            )

        checks.append(self._ti_check(analysis.ti_results))
        return checks

    @staticmethod
    def _ti_check(results: list[ProviderResult]) -> dict[str, Any]:
        """Which real providers answered, which failed (and why), or that none is enabled."""

        def names(rows: list[ProviderResult]) -> str:
            return ", ".join(sorted({PROVIDER_NAMES.get(r.provider, r.provider) for r in rows}))

        def failures(rows: list[ProviderResult]) -> str:
            default = {TIStatus.UNAVAILABLE: "no answer", TIStatus.ERROR: "configuration problem"}
            return ", ".join(
                f"{PROVIDER_NAMES.get(r.provider, r.provider)} ({r.detail or default[r.status]})"
                for r in sorted(rows, key=lambda r: r.provider)
            )

        real = [r for r in results if not r.limited and r.status != TIStatus.DISABLED]
        answered = [r for r in real if r.status in DEFINITIVE_STATUSES]
        failed = [r for r in real if r.status in FAILED_STATUSES]
        demo_answered = any(r.limited and r.status in DEFINITIVE_STATUSES for r in results)
        if answered and not failed:
            status, detail = "completed", names(answered)
        elif answered:
            status = "incomplete"
            detail = f"answered: {names(answered)}; could not be checked: {failures(failed)}"
        elif failed:
            status, detail = "unavailable", f"could not be checked: {failures(failed)}"
        elif demo_answered:
            status = "limited"
            detail = "no real provider is enabled; only QRGUARD's demo blocklist was checked"
        else:
            status, detail = "not_run", "no threat-intelligence provider is enabled"
        return {
            "id": "threat_intelligence",
            "label": "Threat-intelligence databases",
            "status": status,
            "detail": detail,
        }

    # ----- response -----------------------------------------------------------------------------
    def build_response(
        self, analysis: UrlAnalysis, result: ScoreResult, input_type: str = "url"
    ) -> dict[str, Any]:
        """Public form of the URL response, reused for links decoded from QR codes."""
        return self._response(analysis, result, input_type)

    def _response(
        self, analysis: UrlAnalysis, result: ScoreResult, input_type: str = "url"
    ) -> dict[str, Any]:
        parsed = analysis.parsed
        ti_configured = self.threat_intel.configured
        return {
            "input_type": input_type,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "confidence": result.confidence,
            "verification": result.verification,
            "summary": summary_for(result.risk_level, result.verification["status"], input_type),
            "categories": result.categories,
            "indicators": result.indicators,
            "recommendation": recommendation_for(
                result.risk_level, result.verification["status"], result.indicator_ids, input_type
            ),
            "score_breakdown": result.breakdown,
            "threat_intel": {
                "checked": ti_configured,
                "providers": [r.to_public_dict() for r in analysis.ti_results],
                "note": self.threat_intel.note(
                    analysis.ti_results,
                    "Threat-intelligence lookups are not enabled; this result is based on the "
                    "link's structure only.",
                ),
            },
            "checks": self._checks(analysis),
            "analysis": {
                "input_url": parsed.original,
                "normalized_url": parsed.normalized,
                "scheme": parsed.scheme,
                "host": parsed.host or None,
                "host_unicode": parsed.host_unicode if parsed.host_unicode != parsed.host else None,
                "domain": parsed.registrable_domain or None,
                "subdomain": parsed.subdomain or None,
                "public_suffix": parsed.suffix or None,
                "port": parsed.port,
                "brand": analysis.brand.to_dict() if analysis.brand else None,
                "features": analysis.features,
                "redirects": analysis.redirects,
            },
            "disclaimer": DISCLAIMER,
        }
