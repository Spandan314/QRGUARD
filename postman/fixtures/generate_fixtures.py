"""Regenerate the Postman screenshot and QR fixtures (DEMO / TEST DATA, synthetic, no real data).

Run from backend/ with the virtual environment active:
    python ../postman/fixtures/generate_fixtures.py
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "backend"))

from tests.images import blank, png_with_declared_size, qr_png  # noqa: E402
from tests.images import render_text as _render  # noqa: E402


def render_text(lines, **kwargs):
    # Phone-screenshot-like text size; very small text is misread by OCR (see limitations).
    return _render(lines, size=32, width=1100, **kwargs)

FIXTURES = {
    "scam-kyc.png": render_text([
        "Demo / test data",
        "Dear customer, your SBI account will be BLOCKED today.",
        "Update your KYC immediately: http://sbi-kyc-update.xyz/login",
    ]),
    "genuine-otp.png": render_text([
        "Demo / test data",
        "482913 is your OTP for login. Never share your OTP",
        "with anyone. -HDFC Bank",
    ]),
    "upi-dark.jpg": render_text([
        "Demo / test data",
        "You received Rs 5000 cashback.",
        "Enter your UPI PIN to receive the amount.",
    ], dark=True, fmt="JPEG"),
    "lookalike-link.png": render_text([
        "Demo / test data",
        "Your reward points expire today.",
        "Redeem: https://flipkrat.com/rewards",
    ]),
    "blank.png": blank(),
    "decompression-bomb.png": png_with_declared_size(60000, 60000),
    # QR codes (synthetic payloads; the look-alike domain and UPI handles are fictitious)
    "qr-trusted-link.png": qr_png("https://www.wikipedia.org/"),
    "qr-lookalike-link.png": qr_png("https://flipkrat.com/rewards"),
    "qr-upi-refund.png": qr_png(
        "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund"
    ),
    "qr-inverted-upi-shop.png": qr_png(
        "upi://pay?pa=sharmastores@okdemo&pn=Sharma%20Stores", invert=True
    ),
    "qr-multiple.png": qr_png("https://www.wikipedia.org/", "javascript:alert(1)"),
}

for name, data in FIXTURES.items():
    (HERE / name).write_bytes(data)
(HERE / "not-an-image.txt").write_text("DEMO / TEST DATA: this is not an image.\n")
truncated = FIXTURES["scam-kyc.png"]
(HERE / "truncated.png").write_bytes(truncated[: len(truncated) // 2])
print("fixtures written to", HERE)
