import pytest

from app.scoring.engine import ScoringContext, UnknownIndicatorError, score_indicators
from app.scoring.indicator import Indicator
from app.scoring.settings import load_scoring_settings
from app.threat_intelligence.base import ProviderResult, TIStatus

S = load_scoring_settings()


def score(ids, modules=("url_qr",), ti=None, **ctx):
    return score_indicators(S, [Indicator(i) for i in ids], set(modules), ti, ScoringContext(**ctx))


def contributions_total(result):
    return round(sum(i["score_contribution"] for i in result.indicators), 1)


def test_no_indicators_is_safe_but_unverified():
    result = score([])
    assert (result.risk_score, result.risk_level, result.confidence) == (0, "SAFE", "LOW")
    assert result.verification["status"] == "UNVERIFIED"
    assert result.verification["source"] is None
    assert "does not guarantee" in result.verification["message"]


def test_trusted_domain_without_findings_is_safe_and_verified():
    result = score(["TRUSTED_DOMAIN"])
    assert result.risk_level == "SAFE" and result.risk_score == 0
    assert result.verification["status"] == "VERIFIED"
    assert result.verification["source"] == "trusted_domain_list"


def test_medium_finding_prevents_trusted_list_verification():
    result = score(["TRUSTED_DOMAIN", "URL_SHORTENER"])
    assert result.risk_score == 0 and result.risk_level == "SAFE"
    assert result.verification["status"] == "UNVERIFIED"


def test_low_finding_on_trusted_domain_can_still_be_verified():
    assert score(["TRUSTED_DOMAIN", "URL_LONG"]).verification["status"] == "VERIFIED"


def test_verification_never_changes_score_or_level():
    verified = score(["TRUSTED_DOMAIN", "URL_LONG"])  # -20 + 5
    unverified = score(["URL_LONG"])  # 5
    assert verified.verification["status"] != unverified.verification["status"]
    assert verified.risk_level == unverified.risk_level == "SAFE"
    assert verified.risk_score == 0 and unverified.risk_score == 5  # only the -20 weight differs


def test_url_only_score_is_not_diluted_by_missing_modules():
    result = score(["URL_IP_HOST", "URL_NO_HTTPS", "URL_PHISHING_KEYWORD"])  # 25 + 8 + 5
    assert result.risk_score == 38 and result.risk_level == "SUSPICIOUS"
    modules = {m["module"]: m for m in result.breakdown["modules"]}
    assert modules["url_qr"]["effective_weight"] == 1.0
    assert modules["message"]["applicable"] is False


def test_category_cap_limits_one_kind_of_evidence():
    ids = ["URL_IP_HOST", "URL_USERINFO_AT", "URL_OBFUSCATED_IP", "URL_NO_HTTPS", "URL_SHORTENER"]
    result = score(ids)  # 25+20+15+8+10 = 78 url_structure points, capped at 45
    assert result.risk_score == 45
    assert contributions_total(result) == pytest.approx(45, abs=0.2)


def test_keyword_cap():
    result = score(["URL_PHISHING_KEYWORD"] * 5)  # 25 points, lexical cap 15
    assert result.risk_score == 15


def test_contributions_add_up_to_weighted_score():
    result = score(["URL_IP_HOST", "URL_SUSPICIOUS_TLD", "BRAND_IN_DOMAIN_NAME", "TRUSTED_DOMAIN"])
    assert contributions_total(result) == pytest.approx(result.breakdown["weighted_score"], abs=0.2)


def test_lookalike_floor_forces_malicious():
    result = score(["BRAND_LOOKALIKE"])  # 40 points, floor 60
    assert (result.risk_score, result.risk_level, result.confidence) == (60, "MALICIOUS", "HIGH")
    assert result.breakdown["floor_applied"] == {
        "indicator": "BRAND_LOOKALIKE",
        "minimum_score": 60,
        "points_added": 20.0,
    }


def test_brand_name_alone_never_reaches_malicious():
    assert score(["BRAND_IN_DOMAIN_NAME"]).risk_level == "SAFE"
    assert score(["BRAND_NAME_UNOFFICIAL_DOMAIN"]).risk_level == "SAFE"


def test_threat_intel_listed_enforces_90():
    ti = [ProviderResult("demo", TIStatus.LISTED, "phishing")]
    result = score(["URL_NO_HTTPS"], ti=ti)
    assert result.risk_score == 90 and result.risk_level == "MALICIOUS"
    assert result.confidence == "HIGH"
    assert result.verification["status"] == "VERIFIED"
    assert result.verification["source"] == "threat_intelligence"
    ti_row = next(i for i in result.indicators if i["id"] == "TI_LISTED")
    assert ti_row["evidence"] == "Listed by: demo"
    assert {c["id"] for c in result.categories} >= {"malicious_url"}


def test_not_listed_is_not_evidence_of_safety():
    ti = [ProviderResult("demo", TIStatus.NOT_LISTED)]
    with_ti = score(["URL_IP_HOST", "URL_NO_HTTPS"], ti=ti)
    without = score(["URL_IP_HOST", "URL_NO_HTTPS"])
    assert with_ti.risk_score == without.risk_score == 33
    modules = {m["module"]: m for m in with_ti.breakdown["modules"]}
    assert modules["threat_intel"]["applicable"] is False
    clean = score([], ti=ti)
    assert clean.risk_level == "SAFE"
    assert clean.verification["status"] == "UNVERIFIED"  # a clean lookup is not verification


def test_not_listed_raises_confidence_of_unverified_result():
    assert score([], ti=[ProviderResult("demo", TIStatus.NOT_LISTED)]).confidence == "MEDIUM"


def test_partial_threat_intel_is_weighted_with_url_module():
    ti = [ProviderResult("demo", TIStatus.PARTIAL)]
    result = score(["URL_IP_HOST"], ti=ti)  # (0.35*25 + 0.30*50) / 0.65 = 36.5
    assert result.risk_score == 37 and result.risk_level == "SUSPICIOUS"
    assert result.verification["status"] == "UNVERIFIED"  # partial is not a confirmation


def test_categories_only_for_suspicious_or_malicious():
    assert score(["URL_MIXED_SCRIPT"]).categories == []  # 25 -> SAFE
    labels = {c["id"] for c in score(["URL_MIXED_SCRIPT", "URL_PUNYCODE"]).categories}
    assert labels == {"phishing", "impersonation"}


def test_severity_is_derived_from_weight_and_floor():
    rows = {
        r["id"]: r["severity"]
        for r in score(
            ["URL_NO_HTTPS", "URL_SHORTENER", "URL_IP_HOST", "BRAND_LOOKALIKE", "TRUSTED_DOMAIN"]
        ).indicators
    }
    assert rows == {
        "URL_NO_HTTPS": "low",
        "URL_SHORTENER": "medium",
        "URL_IP_HOST": "high",
        "BRAND_LOOKALIKE": "critical",
        "TRUSTED_DOMAIN": "info",
    }


def test_incomplete_checks_lower_confidence():
    assert score(["URL_IP_HOST", "URL_SHORTENER"], incomplete_checks=True).confidence == "LOW"


def test_unknown_indicator_is_a_programming_error():
    with pytest.raises(UnknownIndicatorError):
        score(["NOT_A_REAL_INDICATOR"])


def test_indicators_are_sorted_by_contribution():
    result = score(["URL_NO_HTTPS", "URL_IP_HOST"])
    assert [i["id"] for i in result.indicators] == ["URL_IP_HOST", "URL_NO_HTTPS"]
