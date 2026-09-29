"""Plain-language summary and recommended action for a scored result."""

from __future__ import annotations

from app.scoring.engine import MALICIOUS, SAFE, SUSPICIOUS, VERIFIED

# SAFE is split by verification status so users never read SAFE as "guaranteed safe".
SAFE_VERIFIED = "SAFE_VERIFIED"
SAFE_UNVERIFIED = "SAFE_UNVERIFIED"

SUMMARIES = {
    MALICIOUS: "Strong warning signs: this link is very likely malicious.",
    SUSPICIOUS: "Several warning signs were found. Treat this link as suspicious.",
    SAFE_VERIFIED: (
        "No significant suspicious indicators detected, and the domain is on QRGUARD's list of "
        "recognised websites."
    ),
    SAFE_UNVERIFIED: (
        "No significant suspicious indicators detected. The link could not be verified, so "
        "this does not guarantee that the website is safe."
    ),
}

RECOMMENDATIONS = {
    MALICIOUS: (
        "Do not open this link and do not enter any personal, banking, OTP, PIN or payment "
        "details. If you already did, contact your bank immediately and change your passwords."
    ),
    SUSPICIOUS: (
        "Avoid opening this link. If you need the service, open the official app or type the "
        "official website address yourself instead of using this link."
    ),
    SAFE_UNVERIFIED: (
        "Open it only if you trust the sender and expected this link. Never enter OTPs, PINs, "
        "passwords or card details on a page reached from a link you received."
    ),
    SAFE_VERIFIED: (
        "No major risks detected. Automated checks can still miss new threats, so stay "
        "cautious before sharing personal or payment details."
    ),
}

# Extra advice added when specific evidence is present (checked in this order).
EXTRA_ADVICE = [
    (
        {
            "BRAND_LOOKALIKE",
            "OFFICIAL_DOMAIN_IN_SUBDOMAIN",
            "OFFICIAL_DOMAIN_IN_USERINFO",
            "BRAND_IN_SUBDOMAIN",
            "BRAND_IN_DOMAIN_NAME",
            "BRAND_NAME_UNOFFICIAL_DOMAIN",
        },
        "This link may be impersonating a well-known brand: use the brand's official app "
        "or website instead.",
    ),
    (
        {"URL_EXECUTABLE_DOWNLOAD"},
        "Do not install apps or files from links; use the official app store.",
    ),
    (
        {"URL_SHORTENER", "REDIRECT_CHECK_INCOMPLETE"},
        "Shortened links hide their destination; ask the sender for the full address.",
    ),
]

REPORTING_ADVICE = "In India, report financial fraud at 1930 or https://cybercrime.gov.in."
DISCLAIMER = "This is an automated security assessment, not a guarantee."


def _key(level: str, verification_status: str) -> str:
    if level != SAFE:
        return level
    return SAFE_VERIFIED if verification_status == VERIFIED else SAFE_UNVERIFIED


def summary_for(level: str, verification_status: str) -> str:
    return SUMMARIES[_key(level, verification_status)]


def recommendation_for(level: str, verification_status: str, indicator_ids: set[str]) -> str:
    key = _key(level, verification_status)
    parts = [RECOMMENDATIONS[key]]
    if key != SAFE_VERIFIED:
        for ids, advice in EXTRA_ADVICE:
            if ids & indicator_ids:
                parts.append(advice)
                break
    if level in (SUSPICIOUS, MALICIOUS):
        parts.append(REPORTING_ADVICE)
    return " ".join(parts)
