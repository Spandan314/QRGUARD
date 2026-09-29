"""Plain-language summary and recommended action for a scored result."""

from __future__ import annotations

from app.scoring.engine import MALICIOUS, SAFE, SUSPICIOUS, VERIFIED

# SAFE is split by verification status so users never read SAFE as "guaranteed safe".
SAFE_VERIFIED = "SAFE_VERIFIED"
SAFE_UNVERIFIED = "SAFE_UNVERIFIED"

SUMMARIES = {
    "url": {
        MALICIOUS: "Strong warning signs: this link is very likely malicious.",
        SUSPICIOUS: "Several warning signs were found. Treat this link as suspicious.",
        SAFE_VERIFIED: (
            "No significant suspicious indicators detected, and the domain is on QRGUARD's "
            "list of recognised websites."
        ),
        SAFE_UNVERIFIED: (
            "No significant suspicious indicators detected. The link could not be verified, "
            "so this does not guarantee that the website is safe."
        ),
    },
    "message": {
        MALICIOUS: "Strong warning signs: this message is very likely a scam.",
        SUSPICIOUS: "Several warning signs were found. Treat this message as suspicious.",
        # Messages are only verified by threat intelligence, which implies MALICIOUS.
        SAFE_VERIFIED: "No significant suspicious indicators detected.",
        SAFE_UNVERIFIED: (
            "No significant suspicious indicators detected. This does not guarantee that the "
            "message is genuine."
        ),
    },
}

RECOMMENDATIONS = {
    "url": {
        MALICIOUS: (
            "Do not open this link and do not enter any personal, banking, OTP, PIN or payment "
            "details. If you already did, contact your bank immediately and change your "
            "passwords."
        ),
        SUSPICIOUS: (
            "Avoid opening this link. If you need the service, open the official app or type "
            "the official website address yourself instead of using this link."
        ),
        SAFE_UNVERIFIED: (
            "Open it only if you trust the sender and expected this link. Never enter OTPs, "
            "PINs, passwords or card details on a page reached from a link you received."
        ),
        SAFE_VERIFIED: (
            "No major risks detected. Automated checks can still miss new threats, so stay "
            "cautious before sharing personal or payment details."
        ),
    },
    "message": {
        MALICIOUS: (
            "Do not reply, call back, click links, pay, or share any OTP, PIN, password or card "
            "details. Block and report the sender. If you already paid or shared details, "
            "contact your bank immediately."
        ),
        SUSPICIOUS: (
            "Do not act on this message. Contact the organisation only through its official "
            "app, website or phone number, not the links or numbers in the message."
        ),
        SAFE_UNVERIFIED: (
            "No action needed, but stay cautious: never share OTPs, PINs or passwords, even "
            "when a message looks genuine."
        ),
        SAFE_VERIFIED: (
            "No action needed, but stay cautious: never share OTPs, PINs or passwords, even "
            "when a message looks genuine."
        ),
    },
}

# Extra advice added for the first matching evidence type (checked in this order).
EXTRA_ADVICE = [
    (
        {"MSG_UPI_PIN_TO_RECEIVE"},
        "You never need to enter your UPI PIN, approve a request or scan a QR code to RECEIVE "
        "money.",
    ),
    (
        {"MSG_OTP_REQUEST", "MSG_CREDENTIAL_REQUEST", "MSG_COMBO_CREDENTIAL_IMPERSONATION"},
        "No bank, company or government office ever asks for your OTP, PIN or password.",
    ),
    (
        {"MSG_REMOTE_ACCESS", "MSG_COMBO_REMOTE_SUPPORT"},
        "Never install screen-sharing apps such as AnyDesk or TeamViewer at a stranger's request.",
    ),
    (
        {"MSG_COMBO_ADVANCE_FEE", "MSG_UPFRONT_FEE"},
        "Genuine jobs, internships, prizes and refunds never ask you to pay a fee first.",
    ),
    (
        {"MSG_UNREALISTIC_RETURNS", "MSG_COMBO_RETURNS_PRIVATE_GROUP"},
        "Guaranteed or very high returns are a classic sign of investment fraud.",
    ),
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
MESSAGE_REPORTING_ADVICE = (
    "Suspected fraud calls and messages can be reported through Chakshu on "
    "https://sancharsaathi.gov.in."
)
DISCLAIMER = "This is an automated security assessment, not a guarantee."


def _key(level: str, verification_status: str) -> str:
    if level != SAFE:
        return level
    return SAFE_VERIFIED if verification_status == VERIFIED else SAFE_UNVERIFIED


def summary_for(level: str, verification_status: str, input_type: str = "url") -> str:
    return SUMMARIES[input_type][_key(level, verification_status)]


def recommendation_for(
    level: str, verification_status: str, indicator_ids: set[str], input_type: str = "url"
) -> str:
    key = _key(level, verification_status)
    parts = [RECOMMENDATIONS[input_type][key]]
    if level in (SUSPICIOUS, MALICIOUS):
        for ids, advice in EXTRA_ADVICE:
            if ids & indicator_ids:
                parts.append(advice)
                break
        parts.append(REPORTING_ADVICE)
        if input_type == "message":
            parts.append(MESSAGE_REPORTING_ADVICE)
    elif key == SAFE_UNVERIFIED and input_type == "url":
        for ids, advice in EXTRA_ADVICE:
            if ids & indicator_ids:
                parts.append(advice)
                break
    return " ".join(parts)
