from PIL import Image

from app.analyzers.qr_decoder import MAX_QR_CODES, decode_qr_codes
from tests.images import qr_image


def canvas(*codes, size=250, invert=False):
    image = Image.new(
        "RGB", (40 + len(codes) * (size + 40), size + 80), "black" if invert else "white"
    )
    for i, code in enumerate(codes):
        image.paste(qr_image(code, size, invert), (40 + i * (size + 40), 40))
    return image


def test_single_code():
    assert decode_qr_codes(canvas("https://example.com/menu")) == ["https://example.com/menu"]


def test_several_codes_in_one_image():
    found = decode_qr_codes(canvas("upi://pay?pa=a@ybl", "https://example.com"))
    assert sorted(found) == ["https://example.com", "upi://pay?pa=a@ybl"]


def test_inverted_dark_mode_code():
    assert decode_qr_codes(canvas("WIFI:T:nopass;S:Cafe;;", invert=True)) == [
        "WIFI:T:nopass;S:Cafe;;"
    ]


def test_no_code():
    assert decode_qr_codes(Image.new("RGB", (400, 300), "white")) == []


def test_large_images_are_downscaled_and_still_decoded():
    big = Image.new("RGB", (3500, 2500), "white")
    big.paste(qr_image("https://example.com/big", 900), (1000, 700))
    assert decode_qr_codes(big) == ["https://example.com/big"]


def test_at_most_max_codes_are_returned():
    codes = [f"https://example.com/{i}" for i in range(MAX_QR_CODES + 2)]
    assert len(decode_qr_codes(canvas(*codes, size=200))) <= MAX_QR_CODES
