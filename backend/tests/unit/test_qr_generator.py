import base64
import io

import pytest
from PIL import Image

from app.analyzers.qr_decoder import decode_qr_codes
from app.analyzers.url_rules import load_url_rules
from app.errors import APIError
from app.services.qr_generator import build_payload, escape_wifi, generate, mask_payload

RULES = load_url_rules()


@pytest.mark.parametrize(
    ("kind", "data", "payload"),
    [
        ("text", {"text": "Hello"}, "Hello"),
        ("url", {"url": "HTTPS://Example.com/menu"}, "https://example.com/menu"),
        ("wifi", {"ssid": "Home", "password": "secret123"}, "WIFI:T:WPA;S:Home;P:secret123;;"),
        ("wifi", {"ssid": "Cafe", "security": "nopass"}, "WIFI:T:nopass;S:Cafe;;"),
        (
            "wifi",
            {"ssid": "A;B", "password": "p:ss,word\\1", "hidden": "true"},
            "WIFI:T:WPA;S:A\;B;P:p\\:ss\\,word\\\\1;H:true;;",
        ),
        (
            "wifi",
            {"ssid": "New", "password": "secret123", "security": "WPA3"},
            "WIFI:T:SAE;S:New;P:secret123;;",
        ),
        ("email", {"to": "help@example.com"}, "mailto:help@example.com"),
        (
            "email",
            {"to": "help@example.com", "subject": "Hi there", "body": "a&b"},
            "mailto:help@example.com?subject=Hi%20there&body=a%26b",
        ),
        ("phone", {"number": "+91 98765-43210"}, "tel:+919876543210"),
    ],
)
def test_payloads(kind, data, payload):
    assert build_payload(kind, data, RULES) == payload


@pytest.mark.parametrize(
    ("kind", "data"),
    [
        ("text", {"text": ""}),
        ("text", {"text": "x" * 1001}),
        ("url", {"url": "javascript:alert(1)"}),
        ("url", {"url": "example.com"}),  # must be a complete http(s) address
        ("url", {"url": "ftp://files.example.com"}),
        ("wifi", {"ssid": "", "password": "secret123"}),
        ("wifi", {"ssid": "Home", "password": "short"}),
        ("wifi", {"ssid": "Home", "security": "nopass", "password": "secret123"}),
        ("wifi", {"ssid": "Home", "security": "XYZ", "password": "secret123"}),
        ("wifi", {"ssid": "Home", "password": "secret123", "hidden": "maybe"}),
        ("email", {"to": "not-an-email"}),
        ("phone", {"number": "call me"}),
        ("text", {"text": "hi", "extra": "field"}),
    ],
)
def test_invalid_inputs(kind, data):
    with pytest.raises(APIError) as err:
        build_payload(kind, data, RULES)
    assert (err.value.status, err.value.code) == (400, "VALIDATION_ERROR")


def test_escape_and_mask():
    assert escape_wifi('a\\b;c,d:e"f') == 'a\\\\b\;c\\,d\\:e\\"f'
    assert mask_payload("wifi", "WIFI:T:WPA;S:Home;P:se\;cret;;") == "WIFI:T:WPA;S:Home;P:***;;"
    assert mask_payload("text", "P:not-a-password") == "P:not-a-password"


@pytest.mark.parametrize(
    ("kind", "data"),
    [
        ("text", {"text": "Hello QRGUARD"}),
        ("wifi", {"ssid": "A;B", "password": "p:ss,word1"}),
        ("url", {"url": "https://example.com/menu?table=4"}),
    ],
)
def test_generated_png_decodes_back_to_the_exact_payload(kind, data):
    result = generate(kind, data, "png", 400, RULES)
    image = Image.open(io.BytesIO(base64.b64decode(result["image_base64"])))
    assert decode_qr_codes(image) == [build_payload(kind, data, RULES)]
    assert result["mime"] == "image/png"


def test_svg_output_and_size():
    result = generate("text", {"text": "hi"}, "svg", 256, RULES)
    assert result["mime"] == "image/svg+xml" and result["svg"].lstrip().startswith("<")
    png = generate("text", {"text": "hi"}, "png", 512, RULES)
    width = Image.open(io.BytesIO(base64.b64decode(png["image_base64"]))).width
    assert 400 <= width <= 512
