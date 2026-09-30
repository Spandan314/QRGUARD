import pytest

from app.analyzers.qr_payload import classify, payload_indicators
from app.analyzers.url_rules import load_url_rules
from app.services.qr_analysis_service import safe_display

RULES = load_url_rules()


def parse(content):
    return classify(content, RULES.dangerous_schemes)


def ids(content):
    return [i.id for i in payload_indicators(parse(content), RULES)]


@pytest.mark.parametrize(
    ("content", "kind"),
    [
        ("https://example.com/menu", "url"),
        ("HTTP://EXAMPLE.COM", "url"),
        ("www.example.com", "url"),
        ("javascript:alert(1)", "dangerous"),
        ("intent://scan/#Intent;end", "dangerous"),
        ("upi://pay?pa=shop@okaxis", "upi"),
        ("WIFI:T:WPA;S:Home;P:secret123;;", "wifi"),
        ("mailto:help@example.com?subject=Hi", "email"),
        ("MATMSG:TO:help@example.com;SUB:Hi;BODY:Hello;;", "email"),
        ("tel:+919876543210", "phone"),
        ("SMSTO:57575:START", "sms"),
        ("sms:+919876543210?body=hello", "sms"),
        ("geo:18.52,73.85", "geo"),
        ("BEGIN:VCARD\nFN:Asha\nEND:VCARD", "vcard"),
        ("MECARD:N:Asha;TEL:123;;", "vcard"),
        ("market://details?id=com.example", "app_link"),
        ("whatsapp://send?phone=91", "app_link"),
        ("Hello, this is plain text", "text"),
        ("12345", "text"),
    ],
)
def test_classify(content, kind):
    assert parse(content).content_type == kind


def test_upi_parsing():
    p = parse(
        "upi://pay?pa=Shop.123@okaxis&pn=Sharma%20Kirana&am=250.50&cu=INR&tn=Bill%2042"
    ).parsed
    assert p == {
        "action": "pay",
        "payee_vpa": "Shop.123@okaxis",
        "payee_name": "Sharma Kirana",
        "amount": "250.50",
        "currency": "INR",
        "note": "Bill 42",
        "merchant_code": None,
        "valid_vpa": True,
        "valid_amount": True,
    }


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("upi://pay?pa=shop123@okaxis&pn=Sharma%20Kirana", ["QR_UPI_PAYMENT"]),
        (
            "upi://pay?pa=shop123@okaxis&pn=Sharma%20Kirana&am=250",
            ["QR_UPI_PAYMENT", "QR_UPI_PREFILLED_AMOUNT"],
        ),
        (
            "upi://pay?pa=rahul9876@ybl&pn=SBI%20Customer%20Care",
            ["QR_UPI_PAYMENT", "QR_UPI_NAME_MISMATCH", "QR_UPI_PRETEXT"],
        ),
        ("upi://pay?pa=sbi.refund@sbi&pn=SBI", ["QR_UPI_PAYMENT"]),  # handle matches the brand
        ("upi://pay?pa=x123@ybl&pn=Shop&tn=KYC%20refund", ["QR_UPI_PAYMENT", "QR_UPI_PRETEXT"]),
        ("upi://pay?pn=NoPayee", ["QR_UPI_PAYMENT", "QR_UPI_MALFORMED"]),
        (
            "upi://pay?pa=bad-vpa&am=12abc",
            ["QR_UPI_PAYMENT", "QR_UPI_MALFORMED", "QR_UPI_PREFILLED_AMOUNT"],
        ),
    ],
)
def test_upi_indicators(content, expected):
    assert ids(content) == expected


def test_wifi_parsing_handles_escapes_and_never_exposes_the_password():
    payload = parse(r"WIFI:T:WPA;S:My\;Home\:Net;P:Zq9\;SECRET\\word;H:true;;")
    assert payload.parsed == {
        "ssid": "My;Home:Net",
        "security": "WPA",
        "hidden": True,
        "has_password": True,
    }
    assert "SECRET" not in str(payload.public())
    shown = safe_display(payload)
    assert "SECRET" not in shown and "P:***;" in shown


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("WIFI:T:nopass;S:Free;;", ["QR_WIFI_OPEN"]),
        ("WIFI:S:NoType;;", ["QR_WIFI_OPEN"]),
        ("WIFI:T:WEP;S:Old;P:12345;;", ["QR_WIFI_WEAK_SECURITY"]),
        ("WIFI:T:WPA;S:Good;P:longpassword;;", []),
        ("tel:+91", ["QR_PHONE_NUMBER"]),
        ("SMSTO:57575:START", ["QR_SMS_PREFILLED"]),
        ("SMSTO:57575", ["QR_PHONE_NUMBER"]),
        ("mailto:a@example.com", ["QR_EMAIL"]),
        ("geo:1,2", ["QR_GEO_LOCATION"]),
        ("market://details?id=x", ["QR_APP_LINK"]),
        ("https://example.com", []),
        ("plain text", []),
    ],
)
def test_other_payload_indicators(content, expected):
    assert ids(content) == expected


def test_text_for_rules():
    assert parse("SMSTO:57575:Share your OTP").text_for_rules == "Share your OTP"
    assert parse("mailto:a@example.com?body=Pay%20now").text_for_rules == "Pay now"
    vcard = parse("BEGIN:VCARD\nVERSION:3.0\nFN:Support\nURL:https://x.example\nEND:VCARD")
    assert vcard.text_for_rules == "Support\nhttps://x.example"
    assert parse("Plain words").text_for_rules == "Plain words"
    assert parse("https://example.com").text_for_rules is None
