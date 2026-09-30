"""Classify and parse what a QR code contains, and flag QR-specific risks.

A QR code can hold much more than a web link. QRGUARD recognises:

    url           http(s):// or www. links            -> existing URL analyzer
    dangerous     javascript:, data:, intent: ...      -> existing URL analyzer (flags them)
    upi           upi://pay?pa=...                     -> UPI checks below
    wifi          WIFI:T:WPA;S:name;P:password;;       -> Wi-Fi checks (password never returned)
    email         mailto: / MATMSG:                    -> informational
    phone         tel:                                 -> informational
    sms           sms: / smsto:                        -> pre-filled text checked by scam rules
    geo           geo:lat,long                         -> informational
    vcard         BEGIN:VCARD / MECARD:                -> text checked by the scam rules
    app_link      any other scheme (market:, tg: ...)  -> opens an app directly
    text          anything else                        -> text checked by the scam rules

Nothing is opened, dialled or connected: this module only reads the content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from app.analyzers.url_rules import UrlRules
from app.scoring.indicator import Indicator

_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.\-]{1,31}):", re.IGNORECASE)
_VPA_RE = re.compile(r"^[a-z0-9.\-_]{2,256}@[a-z][a-z0-9]{1,63}$", re.IGNORECASE)
_AMOUNT_RE = re.compile(r"^\d{1,9}(?:\.\d{1,2})?$")

# Words in a UPI payee name or note that suggest a pretext rather than a normal shop.
UPI_PRETEXT_WORDS = (
    "refund",
    "cashback",
    "prize",
    "lottery",
    "reward",
    "kyc",
    "winner",
    "lucky",
    "bonus",
    "claim",
    "customer care",
    "support",
    "helpline",
    "government",
    "police",
    "rbi",
    "income tax",
    "electricity",
    "verification",
    "unlock",
    "job",
    "registration",
)
BANK_OR_AUTHORITY_WORDS = (
    "bank",
    "rbi",
    "npci",
    "government",
    "govt",
    "police",
    "income tax",
    "customs",
    "court",
    "electricity board",
    "customer care",
)


@dataclass
class QrPayload:
    content_type: str
    raw: str
    parsed: dict[str, Any] = field(default_factory=dict)
    text_for_rules: str | None = None  # text to run through the scam-message rules

    def public(self) -> dict[str, Any]:
        """What the API returns. Wi-Fi passwords are never included."""
        return {"content_type": self.content_type, "parsed": self.parsed}


def _unescape_wifi(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _split_wifi(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in re.split(r"(?<!\\);", body):
        if ":" in part:
            key, _, value = part.partition(":")
            fields[key.strip().upper()] = _unescape_wifi(value)
    return fields


def _contact_values(raw: str) -> list[str]:
    """Only the VALUES of a vCard/MECARD (names, numbers, links), not its property names,
    so that syntax such as "BEGIN:VCARD" is never judged as message text."""
    if raw.lower().startswith("mecard:"):
        parts = re.split(r"(?<!\\);", raw[7:])
    else:
        parts = raw.splitlines()
    values = []
    for part in parts:
        key, sep, value = part.partition(":")
        if sep and value.strip() and key.split(";")[0].upper() not in ("BEGIN", "END", "VERSION"):
            values.append(value.strip())
    return values


def _parse_upi(raw: str) -> dict[str, Any]:
    query = parse_qs(urlsplit(raw).query, keep_blank_values=True)

    def first(key: str) -> str | None:
        values = query.get(key) or query.get(key.upper())
        return unquote(values[0]).strip() if values else None

    vpa = first("pa")
    amount = first("am")
    return {
        "action": urlsplit(raw).netloc.lower() or urlsplit(raw).path.strip("/").lower(),
        "payee_vpa": vpa,
        "payee_name": first("pn"),
        "amount": amount,
        "currency": first("cu") or ("INR" if amount else None),
        "note": first("tn"),
        "merchant_code": first("mc"),
        "valid_vpa": bool(vpa and _VPA_RE.match(vpa)),
        "valid_amount": amount is None or bool(_AMOUNT_RE.match(amount)),
    }


def classify(content: str, dangerous_schemes: list[str]) -> QrPayload:
    raw = content.strip()
    lower = raw.lower()
    scheme_match = _SCHEME_RE.match(raw)
    scheme = scheme_match.group(1).lower() if scheme_match else ""

    if lower.startswith(("http://", "https://", "www.")):
        return QrPayload("url", raw, {"url": raw})
    if scheme in dangerous_schemes:
        return QrPayload("dangerous", raw, {"scheme": scheme})
    if scheme == "upi":
        return QrPayload("upi", raw, _parse_upi(raw))
    if lower.startswith("wifi:"):
        fields = _split_wifi(raw[5:])
        security = (fields.get("T") or "nopass").upper() or "NOPASS"
        return QrPayload(
            "wifi",
            raw,
            {
                "ssid": fields.get("S", ""),
                "security": "NOPASS" if security in ("", "NOPASS") else security,
                "hidden": fields.get("H", "").lower() == "true",
                "has_password": bool(fields.get("P")),
            },
        )
    if scheme == "mailto" or lower.startswith("matmsg:"):
        if scheme == "mailto":
            parts = urlsplit(raw)
            query = parse_qs(parts.query)
            address = unquote(parts.path)
            body = unquote(query.get("body", [""])[0])
        else:
            fields = dict(p.split(":", 1) for p in raw[7:].split(";") if ":" in p)
            address, body = fields.get("TO", ""), fields.get("BODY", "")
        return QrPayload("email", raw, {"to": address, "has_body": bool(body)}, body or None)
    if scheme == "tel":
        return QrPayload("phone", raw, {"number": unquote(raw[4:]).strip()})
    if scheme in ("sms", "smsto", "mms", "mmsto"):
        rest = raw[len(scheme) + 1 :]
        number, _, body = rest.partition(":") if scheme.endswith("to") else rest.partition("?body=")
        body = unquote(body)
        return QrPayload(
            "sms", raw, {"number": number.strip(), "has_body": bool(body)}, body or None
        )
    if scheme == "geo":
        return QrPayload("geo", raw, {"coordinates": raw[4:].split("?")[0]})
    if lower.startswith(("begin:vcard", "mecard:")):
        values = _contact_values(raw)
        return QrPayload("vcard", raw, {"fields": len(values)}, "\n".join(values) or None)
    if (scheme and "://" in raw) or scheme in ("market", "tg", "whatsapp", "fb", "instagram"):
        return QrPayload("app_link", raw, {"scheme": scheme})
    return QrPayload("text", raw, {}, raw)


def _contains_any(text: str | None, words: tuple[str, ...]) -> str | None:
    lowered = (text or "").lower()
    return next((w for w in words if re.search(rf"\b{re.escape(w)}\b", lowered)), None)


def payload_indicators(payload: QrPayload, rules: UrlRules) -> list[Indicator]:
    """QR-specific indicators for non-URL payloads (URLs use the URL analyzer instead)."""
    p = payload.parsed
    found: list[Indicator] = []
    if payload.content_type == "upi":
        found.append(Indicator("QR_UPI_PAYMENT", p.get("payee_vpa") or "no payee"))
        if not p["valid_vpa"] or not p["valid_amount"] or p["action"] not in ("pay", ""):
            found.append(Indicator("QR_UPI_MALFORMED", p.get("payee_vpa") or "missing payee"))
        if p.get("amount"):
            found.append(Indicator("QR_UPI_PREFILLED_AMOUNT", f"₹{p['amount']}"))
        name = p.get("payee_name") or ""
        brand_words = {k for b in rules.brands for k in b.keywords}
        claimed = _contains_any(name, BANK_OR_AUTHORITY_WORDS) or next(
            (w for w in brand_words if re.search(rf"\b{re.escape(w)}\b", name.lower())), None
        )
        handle = (p.get("payee_vpa") or "").split("@")[0].lower()
        if claimed and claimed.replace(" ", "") not in handle:
            found.append(Indicator("QR_UPI_NAME_MISMATCH", f"name mentions '{claimed}'"))
        pretext = _contains_any(f"{name} {p.get('note') or ''}", UPI_PRETEXT_WORDS)
        if pretext:
            found.append(Indicator("QR_UPI_PRETEXT", f"'{pretext}'"))
    elif payload.content_type == "wifi":
        if p["security"] == "NOPASS":
            found.append(Indicator("QR_WIFI_OPEN", p.get("ssid") or "unnamed network"))
        elif p["security"] == "WEP":
            found.append(Indicator("QR_WIFI_WEAK_SECURITY", "WEP"))
    elif payload.content_type == "phone":
        found.append(Indicator("QR_PHONE_NUMBER"))
    elif payload.content_type == "sms":
        found.append(Indicator("QR_SMS_PREFILLED" if p["has_body"] else "QR_PHONE_NUMBER"))
    elif payload.content_type == "email":
        found.append(Indicator("QR_EMAIL"))
    elif payload.content_type == "geo":
        found.append(Indicator("QR_GEO_LOCATION"))
    elif payload.content_type == "app_link":
        found.append(Indicator("QR_APP_LINK", f"{p['scheme']}:"))
    return found
