"""Post-deployment smoke test for a running QRGUARD backend (standard library only).

    python scripts/smoke_test.py https://qrguard-api.onrender.com --web-origin https://qrguard.vercel.app

It only sends synthetic DEMO / TEST inputs, needs no credentials and changes nothing on the server
(no result is saved: save_to_history is never requested). Exit code 0 = every check passed.
The first request after an idle period may take up to a minute on a free Render instance.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

FOREIGN_ORIGIN = "https://not-an-allowed-origin.example"


class CheckFailed(Exception):
    pass


def expect(condition: object, detail: object) -> None:
    """Like assert, but not removed by ``python -O``."""
    if not condition:
        raise CheckFailed(str(detail))


class Response:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body

    def json(self) -> Any:
        return json.loads(self.body or b"null")


def request(
    base: str,
    method: str,
    path: str,
    payload: Any = None,
    headers: dict[str, str] | None = None,
    timeout: float = 90,
) -> Response:
    data = json.dumps(payload).encode() if payload is not None else None
    all_headers = {"Content-Type": "application/json"} if data is not None else {}
    all_headers.update(headers or {})
    # The URL is the operator's own backend, given on the command line.
    req = urllib.request.Request(base + path, data=data, method=method, headers=all_headers)  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310
            return Response(res.status, dict(res.headers), res.read())
    except urllib.error.HTTPError as err:
        return Response(err.code, dict(err.headers), err.read())


def checks(base: str, web_origin: str | None) -> list[tuple[str, Callable[[], None]]]:
    def health() -> None:
        body = request(base, "GET", "/api/health").json()
        expect(body["status"] == "ok", body)
        components = body["components"]
        expect(components["scoring_config"]["status"] == "loaded", components)
        # Printed rather than asserted: the image installs Tesseract, but a host may not.
        print(f"      OCR engine: {components['ocr_engine']}")
        enabled = [p["provider"] for p in components["threat_intel"]["providers"] if p["enabled"]]
        print(f"      threat-intelligence providers enabled: {', '.join(enabled) or 'none'}")

    def security_headers() -> None:
        headers = request(base, "GET", "/api/health").headers
        expect(headers.get("x-content-type-options") == "nosniff", headers)
        expect("default-src 'none'" in headers.get("content-security-policy", ""), headers)
        expect(headers.get("cache-control") == "no-store", headers)

    def blocklisted_link() -> None:
        body = request(
            base, "POST", "/api/analyze/url", {"url": "http://secure-sbi-kyc-update.example/login"}
        ).json()
        expect(body["risk_level"] == "MALICIOUS", body.get("risk_level"))
        expect(body["verification"]["status"] == "VERIFIED", body["verification"])

    def scam_message() -> None:
        text = (
            "Dear customer, your SBI account will be BLOCKED today. Share the OTP and update KYC: "
            "http://sbi-kyc-update.xyz/login"
        )
        body = request(base, "POST", "/api/analyze/message", {"text": text}).json()
        expect(body["risk_level"] in ("SUSPICIOUS", "MALICIOUS"), body.get("risk_level"))

    def upi_qr() -> None:
        content = "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund"
        body = request(
            base, "POST", "/api/analyze/qr", {"content": content, "source": "camera"}
        ).json()
        expect(body["risk_level"] in ("SUSPICIOUS", "MALICIOUS"), body.get("risk_level"))

    def private_address_never_contacted() -> None:
        body = request(base, "POST", "/api/analyze/url", {"url": "http://169.254.169.254/"}).json()
        expect(body["analysis"]["redirects"]["checked"] is False, body["analysis"]["redirects"])

    def validation_error() -> None:
        res = request(base, "POST", "/api/analyze/message", {"text": ""})
        expect(res.status == 400 and res.json()["error"]["code"] == "VALIDATION_ERROR", res.status)

    def history_needs_sign_in() -> None:
        res = request(base, "GET", "/api/history")
        # 401 = sign-in configured (Firebase); 503 = the server runs without Firebase.
        expect(res.status in (401, 503), res.status)
        print(f"      history: {'sign-in required' if res.status == 401 else 'not configured'}")

    def dev_tokens_refused() -> None:
        res = request(base, "GET", "/api/history", headers={"Authorization": "Bearer dev-alice"})
        expect(
            res.status in (401, 503), f"dev token accepted ({res.status}): AUTH_DEV_TOKENS is on"
        )

    def cors_allowed() -> None:
        expect(web_origin, "pass --web-origin")
        res = request(
            base,
            "OPTIONS",
            "/api/analyze/url",
            headers={"Origin": web_origin, "Access-Control-Request-Method": "POST"},
        )
        expect(res.headers.get("access-control-allow-origin") == web_origin, res.headers)

    def cors_refused() -> None:
        res = request(
            base,
            "OPTIONS",
            "/api/analyze/url",
            headers={"Origin": FOREIGN_ORIGIN, "Access-Control-Request-Method": "POST"},
        )
        expect("access-control-allow-origin" not in res.headers, res.headers)

    found = [
        ("health, scoring config loaded", health),
        ("security headers", security_headers),
        ("demo-blocklisted link -> MALICIOUS, VERIFIED", blocklisted_link),
        ("scam message flagged", scam_message),
        ("UPI refund QR flagged", upi_qr),
        ("cloud metadata address never contacted", private_address_never_contacted),
        ("invalid input -> 400 VALIDATION_ERROR", validation_error),
        ("history requires sign-in", history_needs_sign_in),
        ("demo dev tokens refused", dev_tokens_refused),
        ("CORS refuses an unknown origin", cors_refused),
    ]
    if web_origin:
        found.append((f"CORS allows {web_origin}", cors_allowed))
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-test a deployed QRGUARD backend.")
    parser.add_argument("base_url", help="backend URL, e.g. https://qrguard-api.onrender.com")
    parser.add_argument("--web-origin", help="the web app origin that must be allowed by CORS")
    args = parser.parse_args(argv)
    base = args.base_url.rstrip("/")

    failed = 0
    for name, check in checks(base, args.web_origin):
        try:
            check()
            print(f"PASS  {name}")
        except (CheckFailed, KeyError, TypeError, ValueError, OSError) as exc:
            failed += 1
            print(f"FAIL  {name}: {str(exc)[:300]}")
    total = len(checks(base, args.web_origin))
    print(f"\n{total - failed}/{total} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
