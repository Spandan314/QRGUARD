"""Text preprocessing for scam-message analysis.

Two versions of the text exist:
* the original text: never logged or stored, and not echoed back except as short evidence;
* the "detection text": normalised, lower-case, with links/amounts/phones/UPI IDs/e-mails
  replaced by placeholder words, used only for rule matching.

Pipeline (docs/risk-scoring.md, "Scam messages"):
 1. remove control characters; count and remove invisible characters (zero-width, bidi)
 2. Unicode NFKC (full-width / styled letters -> plain letters)
 3. measure style (capital letters, exclamation marks) and script (Latin or not)
 4. de-obfuscate and extract links (hxxp, [.], (dot) ...), replace them with "qrglink"
 5. extract e-mails, UPI IDs, amounts, phone numbers -> placeholders
 6. fold look-alike letters, lower-case, fold leetspeak inside words ("0tp" -> "otp")
 7. collapse repeated letters and spaces, split into sentences
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from app.analyzers.scam_rules import ScamRules
from app.analyzers.url_features import label_scripts
from app.analyzers.url_normalizer import domain_extractor

# Placeholders (unusual words that never occur in real text)
LINK, AMOUNT, PHONE, UPI, EMAIL = "qrglink", "qrgamount", "qrgphone", "qrgupi", "qrgemail"
PLACEHOLDER_DISPLAY = {
    LINK: "[link]",
    AMOUNT: "[amount]",
    PHONE: "[phone number]",
    UPI: "[UPI ID]",
    EMAIL: "[e-mail]",
}

_INVISIBLE_RE = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩­]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# De-obfuscation of defanged links: hxxp://, evil[.]com, evil(dot)com, [:]
_DEFANG = [
    (re.compile(r"\bhxxps?", re.IGNORECASE), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\s?[\[({](?:\.|dot)[\])}]\s?", re.IGNORECASE), lambda m: "."),
    (re.compile(r"\[:\]"), lambda m: ":"),
]

_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'`]+", re.IGNORECASE)
# Bare domains such as "sbi-kyc.xyz/login" (validated against the public suffix list below)
_BARE_DOMAIN_RE = re.compile(
    r"(?<![\w@./-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,5}[a-z]{2,24}"
    r"(?:/[^\s<>\"'`]*)?(?![\w@-])",
    re.IGNORECASE,
)
# Common top-level domains accepted for bare domains without a path (avoids "hello.world").
_BARE_DOMAIN_TLDS = {
    "com",
    "in",
    "net",
    "org",
    "info",
    "xyz",
    "top",
    "online",
    "site",
    "live",
    "link",
    "click",
    "me",
    "io",
    "app",
    "co",
    "ly",
    "gl",
    "gd",
    "shop",
    "store",
    "club",
    "icu",
    "vip",
    "buzz",
    "cc",
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "biz",
    "website",
    "space",
    "fun",
    "cyou",
    "sbs",
    "cfd",
}
_TRAILING_PUNCTUATION = ".,;:!?)]}'\"”’>"

_EMAIL_RE = re.compile(r"\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b", re.IGNORECASE)
_UPI_RE = re.compile(r"\b[\w.-]{3,64}@[a-z][a-z0-9]{1,30}\b(?!\.)", re.IGNORECASE)
_AMOUNT_RE = re.compile(
    r"(?:₹|\brs\.?|\binr)\s?\d[\d,]*(?:\.\d{1,2})?(?:\s?(?:lakhs?|lacs?|crores?|cr|k)\b)?"
    r"|\b\d[\d,]*(?:\.\d{1,2})?\s?(?:rupees|lakhs?|lacs?|crores?)\b",
    re.IGNORECASE,
)
_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"  # Indian mobile
    r"|(?<!\d)1800[\s-]?\d{3}[\s-]?\d{3,4}(?!\d)"  # toll-free
)
_REPEATED_LETTERS_RE = re.compile(r"([a-z])\1{2,}")
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")
_UNIT_WORDS = {
    "am",
    "pm",
    "hrs",
    "hr",
    "th",
    "st",
    "nd",
    "rd",
    "days",
    "day",
    "mins",
    "min",
    "gb",
    "mb",
    "kg",
    "km",
    "lakh",
    "lakhs",
    "cr",
    "k",
    "x",
    "g",
}


@dataclass
class ExtractedLink:
    text: str  # as found (after de-obfuscation)
    deobfuscated: bool
    source: str = "text"  # "text" (found in the text) or "qr" (decoded from a QR code)


@dataclass
class PreprocessedText:
    char_count: int
    detection_text: str
    sentences: list[str]
    links: list[ExtractedLink] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)
    hidden_characters: int = 0
    mixed_script_words: int = 0
    letter_count: int = 0  # letters outside links
    non_latin_ratio: float = 0.0
    caps_ratio: float = 0.0
    max_exclamation_run: int = 0
    exclamation_count: int = 0
    links_deobfuscated: int = 0


def display(text: str) -> str:
    """Replace placeholder words with readable markers for evidence shown to users."""
    for token, label in PLACEHOLDER_DISPLAY.items():
        text = text.replace(token, label)
    return text


def mask_phone(number: str) -> str:
    digits = re.sub(r"\D", "", number)
    return "*" * max(0, len(digits) - 4) + digits[-4:]


def _is_valid_bare_domain(candidate: str) -> bool:
    host, _, path = candidate.partition("/")
    extracted = domain_extractor()(host.lower())
    if not extracted.suffix or not extracted.domain:
        return False
    return bool(path) or extracted.suffix.rsplit(".", 1)[-1] in _BARE_DOMAIN_TLDS


def _extract_links(
    text: str, deobfuscated_spans: list[tuple[int, int]]
) -> tuple[str, list[ExtractedLink]]:
    """Find links (full URLs first, then bare domains), replace them with the link token."""
    found: list[tuple[int, int, str]] = []
    for regex, validate in ((_URL_RE, None), (_BARE_DOMAIN_RE, _is_valid_bare_domain)):
        for match in regex.finditer(text):
            start = match.start()
            value = match.group(0).rstrip(_TRAILING_PUNCTUATION)
            end = start + len(value)
            if not value or any(s < end and start < e for s, e, _ in found):
                continue
            if validate and not validate(value):
                continue
            found.append((start, end, value))
    found.sort()
    links: list[ExtractedLink] = []
    for start, end, value in found:
        if all(value != link.text for link in links):
            defanged = any(s < end and start < e for s, e in deobfuscated_spans)
            links.append(ExtractedLink(value, defanged))
    for start, end, _ in reversed(found):
        text = text[:start] + f" {LINK} " + text[end:]
    return text, links


def _replace_entities(text: str) -> tuple[str, dict[str, list[str]]]:
    entities: dict[str, list[str]] = {
        "emails": [],
        "upi_ids": [],
        "amounts": [],
        "phone_numbers": [],
    }

    def grab(regex: re.Pattern[str], key: str, token: str, transform=lambda v: v) -> None:
        nonlocal text

        def _sub(match: re.Match[str]) -> str:
            value = transform(match.group(0).strip())
            if value not in entities[key]:
                entities[key].append(value)
            return f" {token} "

        text = regex.sub(_sub, text)

    grab(_EMAIL_RE, "emails", EMAIL)
    grab(_UPI_RE, "upi_ids", UPI)
    grab(_AMOUNT_RE, "amounts", AMOUNT)
    grab(_PHONE_RE, "phone_numbers", PHONE, mask_phone)
    return text, entities


def _fold_leetspeak(word: str, subs: dict[str, str]) -> str:
    """Replace digits/symbols that sit inside a word ("p@ssw0rd", "0tp", "1nstall")."""
    if not re.search(r"[a-z]", word) or not re.search(r"[0-9@$]", word):
        return word
    chars = list(word)
    for i, ch in enumerate(chars):
        if ch not in subs and ch != "1":
            continue
        before = chars[i - 1] if i > 0 else ""
        after = word[i + 1 :]
        between_letters = before.isalpha() and after[:1].isalpha()
        at_start = i == 0 and re.match(r"[a-z]{2,}", after) and after not in _UNIT_WORDS
        if between_letters or at_start:
            chars[i] = "i" if ch == "1" else subs[ch]
    return "".join(chars)


def preprocess(raw: str, rules: ScamRules) -> PreprocessedText:
    text = _CONTROL_RE.sub(" ", raw.replace("\t", " "))
    hidden = len(_INVISIBLE_RE.findall(text))
    text = _INVISIBLE_RE.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    char_count = len(text)

    # Defanged links: remember where replacements happened.
    deobfuscated_spans: list[tuple[int, int]] = []
    for regex, repl in _DEFANG:
        new_parts, last, offset = [], 0, 0
        for match in regex.finditer(text):
            replacement = repl(match)
            new_parts.append(text[last : match.start()])
            new_start = match.start() + offset
            deobfuscated_spans.append((new_start - 40, new_start + len(replacement) + 40))
            new_parts.append(replacement)
            offset += len(replacement) - (match.end() - match.start())
            last = match.end()
        new_parts.append(text[last:])
        text = "".join(new_parts)

    text, links = _extract_links(text, deobfuscated_spans)
    text, entities = _replace_entities(text)

    # Style and script measurements (links and entities already removed).
    plain = text
    for token in PLACEHOLDER_DISPLAY:
        plain = plain.replace(token, " ")
    letters = [c for c in plain if c.isalpha()]
    upper = sum(1 for c in letters if c.isupper())
    non_latin = sum(1 for c in letters if not unicodedata.name(c, "").startswith("LATIN"))
    words = re.findall(r"\w+", plain)
    mixed = sum(1 for w in words if len(label_scripts(w)) > 1)
    runs = [len(r) for r in re.findall(r"!+", plain)]

    # Detection text: fold look-alikes, lower-case, leetspeak, repeated letters, spaces.
    detection = "".join(rules.homoglyphs.get(c, c) for c in text).lower()
    subs = {k: v for k, v in rules.ascii_substitutions.items() if k not in {"9"}}
    detection = re.sub(r"[a-z0-9@$]+", lambda m: _fold_leetspeak(m.group(0), subs), detection)
    detection = _REPEATED_LETTERS_RE.sub(r"\1\1", detection)
    detection = re.sub(r"[  ]+", " ", detection)
    sentences = [s.strip() for s in _SENTENCE_SPLIT_RE.split(detection) if s and s.strip()]

    return PreprocessedText(
        char_count=char_count,
        detection_text=detection.strip(),
        sentences=sentences,
        links=links,
        entities=entities,
        hidden_characters=hidden,
        mixed_script_words=mixed,
        letter_count=len(letters),
        non_latin_ratio=round(non_latin / len(letters), 3) if letters else 0.0,
        caps_ratio=round(upper / len(letters), 3) if letters else 0.0,
        max_exclamation_run=max(runs, default=0),
        exclamation_count=sum(runs),
        links_deobfuscated=sum(1 for link in links if link.deobfuscated),
    )
