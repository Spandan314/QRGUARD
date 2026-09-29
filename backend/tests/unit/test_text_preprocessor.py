import pytest

from app.analyzers.scam_rules import load_scam_rules
from app.analyzers.text_preprocessor import display, mask_phone, preprocess
from app.analyzers.url_rules import load_url_rules

RULES = load_scam_rules(load_url_rules())


def pre(text: str):
    return preprocess(text, RULES)


def test_nfkc_turns_styled_letters_into_plain_text():
    assert "otp" in pre("Share your ＯＴＰ now").detection_text
    assert "otp" in pre("Share your 𝐎𝐓𝐏 now").detection_text


def test_invisible_characters_are_counted_and_removed():
    result = pre("sh​are your O‍TP‮")
    assert result.hidden_characters == 3
    assert "share your otp" in result.detection_text


def test_mixed_alphabet_words_are_counted():
    assert pre("Your Pаypal account").mixed_script_words == 1  # Cyrillic "а"


@pytest.mark.parametrize(
    ("text", "link"),
    [
        ("Visit https://sbi-kyc.xyz/login now", "https://sbi-kyc.xyz/login"),
        ("go to www.example.com.", "www.example.com"),
        ("Update at sbi-kyc-update.xyz/login", "sbi-kyc-update.xyz/login"),
        ("(http://x.example.com)", "http://x.example.com"),
        ("open hxxps://evil[.]xyz/pay", "https://evil.xyz/pay"),
        ("site: evil(dot)com", "evil.com"),
    ],
)
def test_link_extraction_and_deobfuscation(text, link):
    result = pre(text)
    assert [x.text for x in result.links] == [link]
    assert "qrglink" in result.detection_text


def test_deobfuscated_links_are_counted():
    assert pre("open hxxps://evil[.]xyz/pay").links_deobfuscated == 1
    assert pre("open https://evil.xyz/pay").links_deobfuscated == 0


def test_link_words_are_not_left_in_the_detection_text():
    result = pre("Click http://secure-kyc-update-login.xyz/verify-otp")
    for word in ("kyc", "verify", "otp", "login"):
        assert word not in result.detection_text


def test_non_links_are_not_extracted():
    assert pre("Hello.How are you? Rs.499 only, e.g. tomorrow").links == []


def test_duplicate_links_are_listed_once():
    assert len(pre("a https://x.com/a b https://x.com/a").links) == 1


def test_entities_are_extracted_and_replaced():
    result = pre(
        "Pay ₹1,999 or Rs.499 or 25 lakh to abc@okaxis, mail help@support.example.com "
        "or call +91 98765 43210 / 1800-123-4567"
    )
    assert result.entities["amounts"] == ["₹1,999", "Rs.499", "25 lakh"]
    assert result.entities["upi_ids"] == ["abc@okaxis"]
    assert result.entities["emails"] == ["help@support.example.com"]
    assert result.entities["phone_numbers"] == ["********3210", "*******4567"]
    for token in ("qrgamount", "qrgupi", "qrgemail", "qrgphone"):
        assert token in result.detection_text


def test_leetspeak_is_folded_only_inside_words():
    text = pre("Send 0TP and p@ssw0rd, 1nstall app. OTP 482913 valid 24hrs till 3pm").detection_text
    assert "send otp" in text and "password" in text and "install" in text
    assert "482913" in text and "24hrs" in text and "3pm" in text


def test_repeated_letters_and_sentences():
    result = pre("URGENTTTT!!! Your account.\nShare OTP now")
    assert "urgentt" in result.detection_text
    assert len(result.sentences) == 3


def test_style_measurements():
    result = pre("CLAIM YOUR PRIZE NOW!!! Hurry!")
    assert result.caps_ratio > 0.8
    assert result.max_exclamation_run == 3 and result.exclamation_count == 4


def test_script_ratio():
    assert pre("आपका खाता बंद कर दिया जाएगा").non_latin_ratio == 1.0
    assert pre("Your account").non_latin_ratio == 0.0


def test_display_and_masking_helpers():
    assert display("pay qrgamount to qrgupi") == "pay [amount] to [UPI ID]"
    assert mask_phone("+91 98765 43210") == "********3210"
