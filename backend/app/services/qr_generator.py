"""QR code generator utility (separate from security analysis).

Builds a correctly escaped payload for text, web links, Wi-Fi, e-mail or phone numbers and
renders it as PNG (base64) or SVG. Inputs are validated; payloads are never logged or stored.
The web and mobile apps can also generate codes locally, so private data such as a Wi-Fi
password need not leave the device at all.
"""

from __future__ import annotations

import base64
import io
import re
from typing import Any
from urllib.parse import quote

import qrcode
import qrcode.image.svg
from qrcode.constants import ERROR_CORRECT_M

from app.analyzers.url_normalizer import URLValidationError, normalize_url
from app.analyzers.url_rules import UrlRules
from app.errors import APIError

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}$")
_PHONE_RE = re.compile(r"^\+?[0-9][0-9 ()\-]{2,19}$")
_WIFI_SECURITY = {
    "WPA": "WPA",
    "WPA2": "WPA",
    "WPA3": "SAE",
    "SAE": "SAE",
    "WEP": "WEP",
    "NOPASS": "nopass",
}
ALLOWED_FIELDS = {
    "text": {"text"},
    "url": {"url"},
    "wifi": {"ssid", "password", "security", "hidden"},
    "email": {"to", "subject", "body"},
    "phone": {"number"},
}


def _invalid(message: str) -> APIError:
    return APIError(400, "VALIDATION_ERROR", message)


def escape_wifi(value: str) -> str:
    """Escape the characters that have a special meaning in WIFI: payloads."""
    return re.sub(r'([\\;,:"])', r"\\\1", value)


def build_payload(kind: str, data: dict[str, str], url_rules: UrlRules) -> str:
    unknown = set(data) - ALLOWED_FIELDS[kind]
    if unknown:
        raise _invalid(f"Unknown field(s) for {kind}: {', '.join(sorted(unknown))}.")

    if kind == "text":
        text = data.get("text", "")
        if not 1 <= len(text) <= 1000:
            raise _invalid("text must be 1 to 1000 characters.")
        return text

    if kind == "url":
        raw = data.get("url", "")
        try:
            parsed = normalize_url(raw, url_rules)
        except URLValidationError as exc:
            raise _invalid(exc.message) from exc
        if parsed.is_dangerous_scheme or parsed.scheme_assumed:
            raise _invalid("url must be a complete http:// or https:// address.")
        return parsed.normalized

    if kind == "wifi":
        ssid = data.get("ssid", "")
        password = data.get("password", "")
        security = _WIFI_SECURITY.get(data.get("security", "WPA").upper())
        hidden = data.get("hidden", "false").lower()
        if not 1 <= len(ssid) <= 32:
            raise _invalid("ssid must be 1 to 32 characters.")
        if security is None:
            raise _invalid("security must be WPA, WPA2, WPA3, WEP or nopass.")
        if hidden not in ("true", "false"):
            raise _invalid("hidden must be 'true' or 'false'.")
        if security == "nopass" and password:
            raise _invalid("An open network (nopass) cannot have a password.")
        if security in ("WPA", "SAE") and not 8 <= len(password) <= 63:
            raise _invalid("password must be 8 to 63 characters for WPA networks.")
        if security == "WEP" and not 1 <= len(password) <= 63:
            raise _invalid("A WEP network needs a password.")
        parts = [f"T:{security}", f"S:{escape_wifi(ssid)}"]
        if password:
            parts.append(f"P:{escape_wifi(password)}")
        if hidden == "true":
            parts.append("H:true")
        return "WIFI:" + ";".join(parts) + ";;"

    if kind == "email":
        to = data.get("to", "")
        if not _EMAIL_RE.match(to):
            raise _invalid("to must be a valid e-mail address.")
        subject, body = data.get("subject", ""), data.get("body", "")
        if len(subject) > 200 or len(body) > 1000:
            raise _invalid("subject (200) or body (1000) is too long.")
        query = "&".join(f"{k}={quote(v)}" for k, v in (("subject", subject), ("body", body)) if v)
        return f"mailto:{to}" + (f"?{query}" if query else "")

    number = data.get("number", "").strip()
    if not _PHONE_RE.match(number):
        raise _invalid("number must be a phone number (digits, spaces, +, -, brackets).")
    return "tel:" + re.sub(r"[ ()\-]", "", number)


def mask_payload(kind: str, payload: str) -> str:
    """The payload as returned by the API: Wi-Fi passwords are masked."""
    if kind == "wifi":
        return re.sub(r"(;P:)((?:\\.|[^;])*)", r"\1***", payload)
    return payload


def render(payload: str, fmt: str, size: int) -> dict[str, Any]:
    qr = qrcode.QRCode(error_correction=ERROR_CORRECT_M, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    modules = qr.modules_count + 2 * qr.border
    qr.box_size = max(1, size // modules)
    if fmt == "svg":
        image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        return {"mime": "image/svg+xml", "svg": image.to_string(encoding="unicode")}
    buffer = io.BytesIO()
    qr.make_image(fill_color="black", back_color="white").save(buffer, format="PNG")
    return {
        "mime": "image/png",
        "image_base64": base64.b64encode(buffer.getvalue()).decode("ascii"),
    }


def generate(
    kind: str, data: dict[str, str], fmt: str, size: int, url_rules: UrlRules
) -> dict[str, Any]:
    payload = build_payload(kind, data, url_rules)
    return {
        "type": kind,
        "payload": mask_payload(kind, payload),
        "format": fmt,
        **render(payload, fmt, size),
    }
