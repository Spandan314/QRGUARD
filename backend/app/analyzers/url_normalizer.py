"""URL validation and normalisation.

Every user-supplied URL is untrusted. Before any analysis it is:

1. cleaned (whitespace, tabs/newlines removed; other control characters rejected),
2. checked for its scheme (http/https analysed, dangerous schemes flagged, others rejected),
3. parsed into parts (user info, host, port, path, query),
4. host converted to its canonical ASCII form (IDNA/punycode) and checked,
5. split into subdomain / registrable domain / public suffix with the bundled
   Public Suffix List (no network access),
6. re-assembled into a normalised URL: lowercase scheme and host, default port removed,
   fragment ("#...") removed, any password masked.

The result is a ``ParsedURL`` that every other analyzer works from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote, urlsplit

import idna
import tldextract

from app.analyzers.url_rules import UrlRules
from app.utils.net_safety import IPAddress, is_disguised_ipv4, parse_ip_literal

DEFAULT_PORTS = {"http": 80, "https": 443}

_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]{0,31}):")
_ASCII_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?$")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


class URLValidationError(ValueError):
    """The input is not a URL we can analyse. ``code`` is returned to the client."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedURL:
    original: str
    normalized: str
    scheme: str
    host: str = ""  # ASCII / punycode form, lowercase
    host_unicode: str = ""  # human-readable form (differs for IDN hosts)
    port: int | None = None  # explicit, non-default port only
    path: str = "/"
    query: str = ""
    userinfo: str | None = None  # text before "@" (password masked)
    ip: IPAddress | None = None
    ip_disguised: bool = False
    host_was_encoded: bool = False
    subdomain: str = ""
    domain_name: str = ""  # registrable label without suffix, e.g. "example"
    suffix: str = ""  # public suffix, e.g. "co.in"
    registrable_domain: str = ""  # e.g. "example.co.in" (or the IP / host)
    has_public_suffix: bool = False
    scheme_assumed: bool = False
    had_backslash: bool = False
    is_dangerous_scheme: bool = False

    @property
    def effective_port(self) -> int:
        return self.port or DEFAULT_PORTS.get(self.scheme, 0)


@lru_cache(maxsize=1)
def domain_extractor() -> tldextract.TLDExtract:
    # suffix_list_urls=() -> use the Public Suffix List snapshot bundled with tldextract.
    # No network access and no cache files. Private suffixes (github.io, web.app, ...) are
    # included, so "evil.github.io" is its own registrable domain, not "github.io".
    return tldextract.TLDExtract(
        suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
    )


def to_ascii_host(host: str) -> str:
    """Convert a hostname to lowercase ASCII (punycode). Raises URLValidationError."""
    host = host.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        raise URLValidationError("INVALID_URL", "The link has no valid domain name.")
    if host.isascii():
        ascii_host = host
    else:
        try:
            ascii_host = idna.encode(host, uts46=True, transitional=False).decode("ascii")
        except idna.IDNAError as exc:
            raise URLValidationError(
                "INVALID_URL", "The domain name contains characters that are not allowed."
            ) from exc
    for label in ascii_host.split("."):
        if not _ASCII_LABEL_RE.match(label):
            raise URLValidationError("INVALID_URL", "The link has an invalid domain name.")
    return ascii_host


def to_unicode_host(ascii_host: str) -> str:
    """Human-readable form of a punycode host (falls back to the ASCII form)."""
    if "xn--" not in ascii_host:
        return ascii_host
    try:
        return idna.decode(ascii_host)
    except idna.IDNAError:
        return ascii_host


def _clean(raw: str) -> str:
    text = raw.strip().strip("<>\"'").strip()
    # Browsers silently remove tabs and newlines inside URLs; we do the same.
    text = re.sub(r"[\t\r\n]", "", text)
    if _CONTROL_CHARS_RE.search(text):
        raise URLValidationError("INVALID_URL", "The link contains invalid control characters.")
    if not text:
        raise URLValidationError("EMPTY_URL", "Please enter a link to check.")
    if " " in text:
        raise URLValidationError("INVALID_URL", "A link cannot contain spaces.")
    return text


def _detect_scheme(text: str, rules: UrlRules) -> str | None:
    """Return the scheme if the text has one, else None ("example.com/path")."""
    match = _SCHEME_RE.match(text)
    if not match:
        return None
    scheme = match.group(1).lower()
    rest = text[match.end() :]
    known = {"http", "https", *rules.dangerous_schemes, *rules.non_web_schemes}
    if rest.startswith("//") or scheme in known:
        return scheme
    # "localhost:8080/x" or "example.com:443" have a port, not a scheme.
    return None


def normalize_url(raw: str, rules: UrlRules) -> ParsedURL:
    """Validate and normalise ``raw``. Raises ``URLValidationError`` for unusable input."""
    text = _clean(raw)
    scheme = _detect_scheme(text, rules)

    if scheme in rules.dangerous_schemes:
        # Not parsed further: it is not a web address. Scoring flags it as dangerous.
        return ParsedURL(
            original=text, normalized=f"{scheme}:…", scheme=scheme, is_dangerous_scheme=True
        )
    if scheme is not None and scheme not in DEFAULT_PORTS:
        raise URLValidationError(
            "UNSUPPORTED_PROTOCOL",
            f'"{scheme}:" links are not web links. Only http:// and https:// links can be checked '
            "here (use the QR analyzer for payment, phone or e-mail codes).",
        )

    scheme_assumed = scheme is None
    if scheme_assumed:
        scheme = "https"
        text = "https:" + text if text.startswith("//") else "https://" + text

    had_backslash = "\\" in text
    if had_backslash:
        text = text.replace("\\", "/")  # what browsers do for http(s) links

    parts = urlsplit(text)
    if not parts.netloc:
        raise URLValidationError("INVALID_URL", "The link has no domain name.")

    userinfo = None
    if "@" in parts.netloc:
        raw_userinfo = parts.netloc.rpartition("@")[0]
        user, _, password = raw_userinfo.partition(":")
        userinfo = unquote(user) + (":***" if password else "")

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise URLValidationError("INVALID_URL", "The link has an invalid port number.") from exc

    raw_host = parts.hostname or ""
    host_was_encoded = "%" in raw_host
    raw_host = unquote(raw_host)

    ip = parse_ip_literal(raw_host) if raw_host else None
    if ip is not None:
        host = str(ip)
        host_unicode = host
        ip_disguised = is_disguised_ipv4(raw_host, ip)
    else:
        host = to_ascii_host(raw_host)
        host_unicode = to_unicode_host(host)
        ip_disguised = False

    port = explicit_port if explicit_port not in (None, DEFAULT_PORTS[scheme]) else None

    if ip is not None:
        subdomain, domain_name, suffix, registrable, has_suffix = "", "", "", host, False
    else:
        extracted = domain_extractor()(host)
        has_suffix = bool(extracted.suffix) and bool(extracted.domain)
        if has_suffix:
            subdomain, domain_name, suffix = extracted.subdomain, extracted.domain, extracted.suffix
            registrable = extracted.top_domain_under_public_suffix
        else:
            # No known public suffix (e.g. "intranet", "demo.test"): use the last two labels.
            labels = host.split(".")
            registrable = ".".join(labels[-2:])
            subdomain = ".".join(labels[:-2])
            domain_name = labels[-2] if len(labels) >= 2 else labels[0]
            suffix = labels[-1] if len(labels) >= 2 else ""

    path = parts.path or "/"
    host_display = f"[{host}]" if ip is not None and ip.version == 6 else host
    netloc = host_display + (f":{port}" if port else "")
    if userinfo:
        netloc = f"{userinfo}@{netloc}"
    normalized = f"{scheme}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")

    return ParsedURL(
        original=raw.strip(),
        normalized=normalized,
        scheme=scheme,
        host=host,
        host_unicode=host_unicode,
        port=port,
        path=path,
        query=parts.query,
        userinfo=userinfo,
        ip=ip,
        ip_disguised=ip_disguised,
        host_was_encoded=host_was_encoded,
        subdomain=subdomain,
        domain_name=domain_name,
        suffix=suffix,
        registrable_domain=registrable,
        has_public_suffix=has_suffix,
        scheme_assumed=scheme_assumed,
        had_backslash=had_backslash,
    )
