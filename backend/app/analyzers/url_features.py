"""Structural and lexical URL features (no network access).

``extract_url_features`` returns two things:

* ``features``: raw measurements (lengths, counts, flags) shown in the API response, and
* ``indicators``: the findings that matter for risk, which the scoring engine weighs.

Every check here is a simple, explainable rule. The lists and thresholds come from
``app/data/url_rules.yaml``.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.analyzers.url_normalizer import ParsedURL
from app.analyzers.url_rules import UrlRules
from app.scoring.indicator import Indicator
from app.utils.net_safety import is_public_ip

SPECIAL_CHARS = set("-_~@%=&!;,$+*'()[]{}|^`<>\"")
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")
# %xx sequences that encode plain letters or digits: there is no legitimate need for these.
_ENCODED_ALNUM_RE = re.compile(r"%(?:3[0-9]|4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa])")
_EMBEDDED_URL_RE = re.compile(r"(?:https?:/|https?%3a%2f|https?:%2f|%2f%2f|//www\.)", re.IGNORECASE)
_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")
MAX_KEYWORD_HITS = 3


def host_matches(host: str, entries: list[str]) -> str | None:
    """Return the entry that ``host`` equals or is a subdomain of, if any."""
    for entry in entries:
        if host == entry or host.endswith("." + entry):
            return entry
    return None


def is_local_host(parsed: ParsedURL, rules: UrlRules) -> bool:
    """True for private IPs and names that only exist on local networks."""
    if parsed.ip is not None:
        return not is_public_ip(parsed.ip)
    if "." not in parsed.host:  # single-label names such as "intranet"
        return True
    return host_matches(parsed.host, rules.local_host_suffixes) is not None


def label_scripts(label: str) -> set[str]:
    """Writing systems (LATIN, CYRILLIC, GREEK, ...) used by the letters of a label."""
    scripts = set()
    for char in label:
        if char.isalpha():
            name = unicodedata.name(char, "")
            if name:
                scripts.add(name.split(" ")[0])
    return scripts


def is_trusted(parsed: ParsedURL, rules: UrlRules) -> bool:
    """Registrable domain is on the trusted list or is a brand's official domain."""
    if parsed.ip is not None or not parsed.has_public_suffix:
        return False
    if host_matches(parsed.host, rules.user_content_hosts):
        return False
    trusted = [*rules.trusted_domains, *rules.official_domains().keys()]
    return host_matches(parsed.registrable_domain, trusted) is not None


def _keyword_hits(parsed: ParsedURL, rules: UrlRules) -> list[str]:
    """Phishing keywords found as words in the host (except the suffix) and path/query."""
    host_part = ".".join(p for p in (parsed.subdomain, parsed.domain_name) if p)
    text = f"{host_part} {parsed.path} {parsed.query}".lower()
    words = [w for w in _WORD_SPLIT_RE.split(text) if w]
    hits: list[str] = []
    for word in words:
        # Each word counts once, as its longest matching keyword ("netbanking" is one hit,
        # not "banking" + "netbanking"). Short keywords must match the whole word; longer
        # ones may be part of a word ("kycupdate" contains "update").
        best = ""
        for keyword in rules.phishing_keywords:
            compact = keyword.replace("-", "")
            matches = word == compact or (len(compact) >= 5 and compact in word)
            if matches and len(compact) > len(best):
                best = compact
        if best and best not in hits:
            hits.append(best)
    return hits


def extract_url_features(
    parsed: ParsedURL, rules: UrlRules
) -> tuple[dict[str, Any], list[Indicator]]:
    limits = rules.limits
    indicators: list[Indicator] = []
    url = parsed.normalized
    path_and_query = parsed.path + ("?" + parsed.query if parsed.query else "")

    subdomain_labels = [x for x in parsed.subdomain.split(".") if x and x != "www"]
    special_count = sum(1 for c in url if c in SPECIAL_CHARS)
    special_ratio = round(special_count / len(url), 3) if url else 0.0
    encoded_count = len(_PERCENT_ENCODED_RE.findall(path_and_query))
    encoded_alnum = bool(_ENCODED_ALNUM_RE.search(path_and_query))
    last_segment = parsed.path.rstrip("/").rsplit("/", 1)[-1].lower()
    extension = last_segment.rsplit(".", 1)[-1] if "." in last_segment else ""
    is_executable = bool(extension) and extension in rules.executable_extensions
    tld = parsed.suffix.rsplit(".", 1)[-1] if parsed.suffix else ""
    suspicious_tld = bool(tld) and tld in rules.suspicious_tlds
    shortener = host_matches(parsed.host, rules.url_shorteners)
    user_content = host_matches(parsed.host, rules.user_content_hosts)
    local = is_local_host(parsed, rules)
    trusted = is_trusted(parsed, rules)
    keyword_hits = _keyword_hits(parsed, rules)
    punycode = any(label.startswith("xn--") for label in parsed.host.split("."))
    mixed_script_labels = [
        label for label in parsed.host_unicode.split(".") if len(label_scripts(label)) > 1
    ]
    hyphens = parsed.domain_name.count("-")

    # ---- indicators ------------------------------------------------------------------------
    if parsed.scheme_assumed:
        indicators.append(Indicator("URL_SCHEME_ASSUMED"))
    if parsed.scheme == "http":
        indicators.append(Indicator("URL_NO_HTTPS", "http://"))
    if parsed.ip is not None:
        indicators.append(Indicator("URL_IP_HOST", parsed.host))
        if parsed.ip_disguised:
            indicators.append(Indicator("URL_OBFUSCATED_IP", f"decodes to {parsed.host}"))
    if local:
        indicators.append(Indicator("URL_PRIVATE_NETWORK_HOST", parsed.host))
    if parsed.userinfo is not None:
        indicators.append(Indicator("URL_USERINFO_AT", f"{parsed.userinfo}@…"))
    if parsed.port is not None:
        indicators.append(Indicator("URL_NONSTANDARD_PORT", f":{parsed.port}"))
    if len(subdomain_labels) > limits.max_subdomains:
        indicators.append(
            Indicator("URL_MANY_SUBDOMAINS", f"{len(subdomain_labels)} subdomain levels")
        )
    if len(url) > limits.very_long_url_length:
        indicators.append(Indicator("URL_VERY_LONG", f"{len(url)} characters"))
    elif len(url) > limits.long_url_length:
        indicators.append(Indicator("URL_LONG", f"{len(url)} characters"))
    if len(url) >= limits.special_char_min_length and special_ratio >= limits.special_char_ratio:
        indicators.append(Indicator("URL_SPECIAL_CHARS", f"{special_count} symbols"))
    if parsed.host_was_encoded or encoded_alnum or encoded_count >= limits.many_encoded_chars:
        indicators.append(Indicator("URL_ENCODED_CHARS", f"{encoded_count} encoded characters"))
    if _EMBEDDED_URL_RE.search(path_and_query):
        indicators.append(Indicator("URL_EMBEDDED_URL"))
    if parsed.had_backslash:
        indicators.append(Indicator("URL_BACKSLASH"))
    if shortener:
        indicators.append(Indicator("URL_SHORTENER", shortener))
    if suspicious_tld:
        indicators.append(Indicator("URL_SUSPICIOUS_TLD", "." + tld))
    if hyphens > limits.max_hyphens_in_domain:
        indicators.append(Indicator("URL_MANY_HYPHENS", f"{hyphens} hyphens"))
    if is_executable:
        indicators.append(Indicator("URL_EXECUTABLE_DOWNLOAD", "." + extension))
    if user_content:
        indicators.append(Indicator("URL_USER_CONTENT_HOST", user_content))
    if punycode:
        indicators.append(Indicator("URL_PUNYCODE", parsed.host_unicode))
    if mixed_script_labels:
        indicators.append(Indicator("URL_MIXED_SCRIPT", mixed_script_labels[0]))
    for keyword in keyword_hits[:MAX_KEYWORD_HITS]:
        indicators.append(Indicator("URL_PHISHING_KEYWORD", keyword))
    if trusted:
        indicators.append(Indicator("TRUSTED_DOMAIN", parsed.registrable_domain))

    features: dict[str, Any] = {
        "url_length": len(url),
        "host_length": len(parsed.host),
        "path_length": len(parsed.path),
        "query_length": len(parsed.query),
        "subdomain_count": len(subdomain_labels),
        "hyphens_in_domain": hyphens,
        "digits_in_host": sum(c.isdigit() for c in parsed.host),
        "special_char_count": special_count,
        "special_char_ratio": special_ratio,
        "encoded_char_count": encoded_count,
        "uses_https": parsed.scheme == "https",
        "is_ip_address": parsed.ip is not None,
        "is_private_or_local": local,
        "has_userinfo": parsed.userinfo is not None,
        "has_nonstandard_port": parsed.port is not None,
        "is_punycode": punycode,
        "is_shortener": shortener is not None,
        "is_user_content_host": user_content is not None,
        "suspicious_tld": suspicious_tld,
        "executable_download": is_executable,
        "phishing_keywords": keyword_hits,
        "is_trusted_domain": trusted,
    }
    return features, indicators
