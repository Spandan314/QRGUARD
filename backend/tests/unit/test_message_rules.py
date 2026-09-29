"""Scam-message rules: one positive and one near-miss example per indicator, negation,
overlap (no double counting), combinations, the no-single-keyword property and ReDoS limits."""

import time
from pathlib import Path

import pytest
import yaml

from app.analyzers.message_analyzer import analyze_message
from app.analyzers.scam_rules import DEFAULT_SCAM_RULES_PATH, ScamRulesError, load_scam_rules
from app.analyzers.text_preprocessor import preprocess
from app.analyzers.url_rules import load_url_rules
from app.scoring.engine import score_indicators
from app.scoring.settings import load_scoring_settings

URL_RULES = load_url_rules()
RULES = load_scam_rules(URL_RULES)
SETTINGS = load_scoring_settings()


def ids(text: str) -> set[str]:
    return analyze_message(preprocess(text, RULES), RULES).ids


def score(text: str):
    findings = analyze_message(preprocess(text, RULES), RULES)
    return score_indicators(SETTINGS, findings.indicators, {"message"}, primary_modules={"message"})


# --- positive / near-miss examples per indicator ------------------------------------------------
CASES = [
    ("MSG_OTP_REQUEST", "Please share the OTP you received", "Your OTP is 482913"),
    ("MSG_OTP_REQUEST", "The verification code, forward it to me", "OTP sent to your number"),
    (
        "MSG_CREDENTIAL_REQUEST",
        "Kindly send your ATM PIN and CVV",
        "Enter your pin code for delivery",
    ),
    (
        "MSG_CREDENTIAL_REQUEST",
        "Verify your net banking password here",
        "Password changed successfully",
    ),
    ("MSG_UPI_PIN_TO_RECEIVE", "Enter your UPI PIN to receive the money", "UPI payment received"),
    (
        "MSG_UPI_PIN_TO_RECEIVE",
        "Scan the QR code to receive your refund",
        "Scan QR to pay the bill",
    ),
    (
        "MSG_REMOTE_ACCESS",
        "Download AnyDesk so our team can help",
        "Download our app from Play Store",
    ),
    ("MSG_ACCOUNT_THREAT", "Your account will be blocked", "To block your card, SMS BLOCK to 5676"),
    ("MSG_ACCOUNT_THREAT", "We will suspend your SIM card", "Your SIM is active"),
    (
        "MSG_LEGAL_THREAT",
        "An arrest warrant is issued in your name",
        "Pay the bill to avoid late fee",
    ),
    (
        "MSG_LEGAL_THREAT",
        "Your electricity will be disconnected tonight",
        "Electricity bill generated",
    ),
    ("MSG_URGENCY", "Respond within 24 hours", "Delivered in 2 days"),
    ("MSG_UPFRONT_FEE", "Pay the registration fee to join", "Delivery charges waived"),
    (
        "MSG_PAYMENT_REQUEST",
        "Transfer Rs 5000 to this account number",
        "Rs 5000 credited to your account",
    ),
    ("MSG_KYC_PRETEXT", "Your KYC is pending, update now", "Thank you for banking with us"),
    ("MSG_REFUND_PRETEXT", "Excess amount credited by mistake", "Refunds take 5 days"),
    ("MSG_UNREALISTIC_RETURNS", "Guaranteed returns on your investment", "Returns policy: 7 days"),
    ("MSG_UNREALISTIC_RETURNS", "Earn 30% daily profit", "Tax at 30% applies"),
    ("MSG_PRIZE_REWARD", "You have won a lucky draw", "Our team won the match yesterday"),
    ("MSG_JOB_LURE", "Work from home and earn Rs 3000 per day", "Your shift starts at 9"),
    ("MSG_TASK_EARNING", "Get paid for liking YouTube videos", "Watch the video on YouTube"),
    (
        "MSG_INTERNSHIP_LURE",
        "Internship with stipend and certificate",
        "Internship interview on Monday",
    ),
    ("MSG_INVESTMENT_TOPIC", "Join our crypto VIP group", "Join our team meeting"),
    ("MSG_OFF_PLATFORM_CONTACT", "Contact us on Telegram", "Contact us at the branch"),
    ("MSG_AUTHORITY_REFERENCE", "This is the cyber cell calling", "This is your friend"),
    ("MSG_SUPPORT_REFERENCE", "Call our customer care", "Call your mother"),
    ("MSG_BANK_REFERENCE", "Your SBI account", "Your library account"),
    ("MSG_SECURITY_ADVICE", "Never share your OTP with anyone", "Share your OTP"),
    ("MSG_SECURITY_ADVICE", "The bank will never ask for your PIN", "The bank will call you"),
]


@pytest.mark.parametrize(("indicator", "positive", "near_miss"), CASES)
def test_indicator_positive_and_near_miss(indicator, positive, near_miss):
    assert indicator in ids(positive)
    assert indicator not in ids(near_miss)


def test_derived_indicators():
    assert "MSG_LINK_CALL_TO_ACTION" in ids("Click here to verify: https://x.example.com")
    assert "MSG_LINK_CALL_TO_ACTION" not in ids("Our website is https://x.example.com")
    assert "MSG_PHONE_CALL_TO_ACTION" in ids("You won a prize! Call 9876543210 now")
    assert "MSG_PHONE_CALL_TO_ACTION" not in ids("Call 9876543210 for delivery")  # no pressure/lure
    assert "MSG_EXCESSIVE_PUNCTUATION" in ids("Claim now!!!")
    assert "MSG_EXCESSIVE_CAPS" in ids("YOUR ACCOUNT HAS BEEN SELECTED FOR REWARD")
    assert "MSG_HIDDEN_CHARACTERS" in ids("sh​are your details")
    assert "MSG_LANGUAGE_NOT_SUPPORTED" in ids("आपका खाता बंद कर दिया जाएगा")


# --- negation -----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "Never share your OTP with anyone.",
        "123456 is your OTP for login. Do not share this code.",
        "Please do not share your PIN or password with anyone",
        "Bank will never ask for your OTP, PIN or CVV",
        "Don't give your CVV to anybody",
        "You don't need to pay any registration fee",
    ],
)
def test_genuine_security_advice_is_not_a_request(text):
    found = ids(text)
    assert not found & {"MSG_OTP_REQUEST", "MSG_CREDENTIAL_REQUEST", "MSG_UPFRONT_FEE"}
    assert score(text).risk_level == "SAFE"


def test_negation_does_not_leak_into_the_next_sentence_or_clause():
    assert "MSG_OTP_REQUEST" in ids("Do not delay. Share the OTP now.")
    assert "MSG_OTP_REQUEST" in ids("Don't worry, just share the OTP with me")


# --- no double counting -------------------------------------------------------------------------
def test_same_words_support_only_one_indicator():
    found = ids("Enter your UPI PIN to receive Rs 500")
    assert "MSG_UPI_PIN_TO_RECEIVE" in found and "MSG_CREDENTIAL_REQUEST" not in found
    found = ids("Pay processing fee Rs 12500 to claim")
    assert "MSG_UPFRONT_FEE" in found and "MSG_PAYMENT_REQUEST" not in found


def test_repeated_phrases_count_once():
    result = score("Urgent! Urgent! Urgent! Act now, hurry, immediately")
    urgency = [i for i in result.indicators if i["id"] == "MSG_URGENCY"]
    assert len(urgency) == 1 and urgency[0]["score_contribution"] == 10


def test_link_text_is_never_counted_as_message_evidence():
    assert ids("https://kyc-update-otp-verify.example.com") == set()


# --- combinations -------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("text", "combo"),
    [
        ("SBI: share the OTP to keep your account active", "MSG_COMBO_CREDENTIAL_IMPERSONATION"),
        ("You won a prize. Pay the processing fee to claim.", "MSG_COMBO_ADVANCE_FEE"),
        ("Refund approved. Enter your UPI PIN to receive it.", "MSG_COMBO_REWARD_CREDENTIAL"),
        (
            "Account will be blocked. Act now: https://x.example.com",
            "MSG_COMBO_THREAT_URGENCY_ACTION",
        ),
        ("SIM will be blocked. Call 9876543210 immediately", "MSG_COMBO_THREAT_URGENCY_ACTION"),
        ("Customer care: install AnyDesk", "MSG_COMBO_REMOTE_SUPPORT"),
        ("Guaranteed returns. Join our Telegram group", "MSG_COMBO_RETURNS_PRIVATE_GROUP"),
    ],
)
def test_combinations_fire_when_all_groups_match(text, combo):
    assert combo in ids(text)


def test_combinations_need_every_group():
    assert "MSG_COMBO_THREAT_URGENCY_ACTION" not in ids(
        "Account will be blocked. Act now."
    )  # no link
    assert "MSG_COMBO_ADVANCE_FEE" not in ids("You won a prize!")


# --- no single keyword / indicator decides ------------------------------------------------------
SINGLE_EXAMPLES = {rule_id: pos for rule_id, pos, _ in CASES}


@pytest.mark.parametrize("indicator", sorted(SINGLE_EXAMPLES))
def test_no_single_indicator_makes_a_message_malicious(indicator):
    assert score(SINGLE_EXAMPLES[indicator]).risk_score < 60


def test_only_explicit_requests_reach_suspicious_alone():
    config = SETTINGS.indicators
    strong = {k for k, v in config.items() if v.module == "message" and v.weight >= 30}
    assert strong == {"MSG_OTP_REQUEST", "MSG_CREDENTIAL_REQUEST", "MSG_UPI_PIN_TO_RECEIVE"}
    caps = {config[k].category for k in config if config[k].module == "message"}
    assert max(SETTINGS.category_caps[c] for c in caps - {"trust"}) < 60
    assert not [k for k, v in config.items() if v.module == "message" and v.floor]


@pytest.mark.parametrize("keyword", ["OTP", "urgent", "KYC", "lottery", "AnyDesk", "bank", "prize"])
def test_single_keywords_are_safe(keyword):
    assert score(keyword).risk_level == "SAFE"


# --- ReDoS / performance ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "share " * 830,
        "!" * 5000,
        "a" * 5000,
        "otp " * 1250,
        ("pay qrg fee " * 500)[:5000],
        "a. " * 1666,
        "http://x.com/" + "a" * 4980,
    ],
)
def test_adversarial_input_is_fast(text):
    start = time.perf_counter()
    analyze_message(preprocess(text, RULES), RULES)
    assert time.perf_counter() - start < 0.5


# --- rule file validation -----------------------------------------------------------------------
def _load_modified(tmp_path: Path, change):
    data = yaml.safe_load(DEFAULT_SCAM_RULES_PATH.read_text(encoding="utf-8"))
    change(data)
    path = tmp_path / "rules.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return load_scam_rules(URL_RULES, path)


def test_nested_quantifier_patterns_are_rejected(tmp_path):
    def change(data):
        data["rules"][0]["patterns"].append("(a+)+b")

    with pytest.raises(ScamRulesError, match="ReDoS"):
        _load_modified(tmp_path, change)


def test_invalid_regex_is_rejected(tmp_path):
    def change(data):
        data["rules"][0]["patterns"].append("(unclosed")

    with pytest.raises(ScamRulesError, match="Invalid regular expression"):
        _load_modified(tmp_path, change)


def test_combination_with_unknown_rule_is_rejected(tmp_path):
    def change(data):
        data["combinations"]["MSG_COMBO_ADVANCE_FEE"]["all_of"].append(["MSG_NOPE"])

    with pytest.raises(ScamRulesError, match="unknown rules"):
        _load_modified(tmp_path, change)
