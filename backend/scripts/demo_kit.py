"""Final-demonstration kit: printable QR codes plus a check that every demo input still gives the
result the runbook promises.

    cd backend
    python -m scripts.demo_kit --check                 # run every scenario through the real API
    python -m scripts.demo_kit --write ../demo-data/demo-kit   # (re)build the printable sheet

All inputs are DEMO / TEST DATA: reserved (.example) or clearly fake domains, fictitious UPI IDs,
synthetic screenshots. Redirect checking is off, so no link is contacted.
"""

from __future__ import annotations

import argparse
import base64
import html
import io
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import qrcode
import yaml

from scripts.evaluate import _client

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "postman" / "fixtures"


@dataclass(frozen=True)
class Scenario:
    number: int
    title: str
    kind: str  # qr | url | message | screenshot
    value: str  # QR content, URL, message id in demo-data/messages.yaml, or fixture file name
    expected: str
    verified: bool = False  # expect verification.status == VERIFIED
    point: str = ""  # what to say during the demo


SCENARIOS = [
    Scenario(
        1,
        "Official website QR",
        "qr",
        "https://www.onlinesbi.sbi/",
        "SAFE",
        True,
        "Trusted domain: SAFE and VERIFIED. The link is never opened automatically.",
    ),
    Scenario(
        2,
        "Look-alike bank login QR",
        "qr",
        "https://sbi-kyc-verify.top/login",
        "SUSPICIOUS",
        point="Brand in a domain it does not own, risky TLD, phishing words.",
    ),
    Scenario(
        3,
        "Known phishing QR (demo blocklist)",
        "qr",
        "http://secure-sbi-kyc-update.example/login",
        "MALICIOUS",
        True,
        "Threat-intelligence hit: MALICIOUS and verified by a threat list.",
    ),
    Scenario(
        4,
        "'Scan to receive your refund' UPI QR",
        "qr",
        "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund",
        "SUSPICIOUS",
        point="Scanning a UPI QR only ever SENDS money; pre-filled amount.",
    ),
    Scenario(
        5,
        "Shop UPI QR",
        "qr",
        "upi://pay?pa=shop.demo@okaxis&pn=Demo%20Tea%20Stall",
        "SAFE",
        point="Ordinary payment QR: SAFE but UNVERIFIED (not a guarantee).",
    ),
    Scenario(
        6,
        "Typosquatted shopping link",
        "url",
        "https://amaz0n-offers.example/deal",
        "MALICIOUS",
        point="Look-alike of a known brand (0 instead of o).",
    ),
    Scenario(
        7,
        "Genuine bank OTP SMS",
        "message",
        "genuine-otp-1",
        "SAFE",
        point="'Never share your OTP' is recognised as genuine advice.",
    ),
    Scenario(
        8,
        "Fake KYC SMS with link",
        "message",
        "scam-kyc-link",
        "MALICIOUS",
        point="Threat + urgency + look-alike link, combined and explained.",
    ),
    Scenario(
        9,
        "Fake internship offer",
        "message",
        "scam-internship",
        "MALICIOUS",
        point="Job offer + registration fee combination.",
    ),
    Scenario(
        10,
        "Scam screenshot",
        "screenshot",
        "scam-kyc.png",
        "MALICIOUS",
        point="OCR reads the text; the text is analysed and then discarded.",
    ),
    Scenario(11, "Genuine OTP screenshot", "screenshot", "genuine-otp.png", "SAFE"),
]


def _messages() -> dict[str, str]:
    data = yaml.safe_load((ROOT / "demo-data" / "messages.yaml").read_text(encoding="utf-8"))
    return {m["id"]: m["text"] for m in data["messages"]}


def display_value(scenario: Scenario, messages: dict[str, str]) -> str:
    return messages[scenario.value] if scenario.kind == "message" else scenario.value


def analyse(client, scenario: Scenario, messages: dict[str, str]) -> dict[str, Any]:
    if scenario.kind == "qr":
        response = client.post(
            "/api/analyze/qr", json={"content": scenario.value, "source": "camera"}
        )
    elif scenario.kind == "url":
        response = client.post("/api/analyze/url", json={"url": scenario.value})
    elif scenario.kind == "message":
        response = client.post("/api/analyze/message", json={"text": messages[scenario.value]})
    else:
        with (FIXTURES / scenario.value).open("rb") as image:
            response = client.post(
                "/api/analyze/screenshot",
                data={"file": (image, scenario.value)},
                content_type="multipart/form-data",
            )
    return {"status": response.status_code, **(response.get_json() or {})}


def check(include_screenshots: bool = True) -> list[str]:
    """Return a list of scenarios whose live result differs from the runbook."""
    client = _client()
    messages = _messages()
    problems = []
    for scenario in SCENARIOS:
        if scenario.kind == "screenshot" and not include_screenshots:
            continue
        body = analyse(client, scenario, messages)
        level = body.get("risk_level", f"HTTP {body['status']}")
        verified = (body.get("verification") or {}).get("status") == "VERIFIED"
        ok = level == scenario.expected and (verified or not scenario.verified)
        print(
            f"{'PASS' if ok else 'FAIL'}  {scenario.number:>2}. {scenario.title}: {level} "
            f"{body.get('risk_score', '')} {'VERIFIED' if verified else 'UNVERIFIED'}"
        )
        if not ok:
            problems.append(f"{scenario.number}. {scenario.title}: got {level}")
    return problems


def _qr_png(content: str) -> bytes:
    buffer = io.BytesIO()
    qrcode.make(content, border=4, box_size=10).save(buffer, format="PNG")
    return buffer.getvalue()


def write(directory: Path) -> None:
    """Write one PNG per QR scenario and a single printable HTML sheet (images inlined)."""
    directory.mkdir(parents=True, exist_ok=True)
    cards = []
    for scenario in (s for s in SCENARIOS if s.kind == "qr"):
        png = _qr_png(scenario.value)
        (directory / f"qr-{scenario.number:02d}.png").write_bytes(png)
        data = base64.b64encode(png).decode()
        verified = " · VERIFIED" if scenario.verified else ""
        cards.append(
            f'<figure><img alt="QR {scenario.number}" src="data:image/png;base64,{data}">'
            f"<figcaption><b>{scenario.number}. {html.escape(scenario.title)}</b><br>"
            f"Expected: <b>{scenario.expected}</b>{verified}<br>"
            f"<small>{html.escape(scenario.point)}</small></figcaption></figure>"
        )
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>QRGUARD demo QR codes</title>
<style>
body{{font-family:system-ui,sans-serif;margin:16px;color:#111;background:#fff}}
h1{{font-size:20px}} p{{font-size:13px}}
main{{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px}}
figure{{margin:0;border:1px solid #bbb;border-radius:8px;padding:12px;break-inside:avoid}}
img{{width:200px;height:200px;image-rendering:pixelated;display:block;margin:0 auto 8px}}
figcaption{{font-size:13px;line-height:1.4}}
</style></head><body>
<h1>QRGUARD final demonstration: QR codes</h1>
<p><b>DEMO / TEST DATA.</b> Every link uses a reserved (.example) or fake domain and every UPI ID is
fictitious. Print this page (or show it on a second screen) and scan each code with the QRGUARD app.
Generated by <code>backend/scripts/demo_kit.py</code>; see <code>docs/demo-runbook.md</code>.</p>
<main>{"".join(cards)}</main></body></html>
"""
    (directory / "index.html").write_text(page, encoding="utf-8")
    print(f"wrote {len(cards)} QR codes and index.html to {directory}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="verify every scenario")
    parser.add_argument("--write", type=Path, help="write the printable QR sheet to this folder")
    args = parser.parse_args(argv)
    if not (args.check or args.write):
        parser.error("use --check and/or --write DIR")
    if args.write:
        write(args.write)
    if args.check:
        problems = check()
        print(f"\n{len(SCENARIOS) - len(problems)}/{len(SCENARIOS)} scenarios as expected")
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
