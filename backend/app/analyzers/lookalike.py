"""Brand impersonation and look-alike domain detection (practical MVP).

The checks, from strongest to weakest:

1. OFFICIAL_DOMAIN_IN_SUBDOMAIN  sbi.co.in.kyc-update.xyz  (real address used as a prefix)
2. OFFICIAL_DOMAIN_IN_USERINFO   https://www.sbi.co.in@evil.xyz
3. BRAND_LOOKALIKE               paypa1.com, hdfcbnak.com, аpple.com (Cyrillic "а")
4. BRAND_IN_SUBDOMAIN            paytm.secure-login.xyz
5. BRAND_NAME_UNOFFICIAL_DOMAIN  paypal.xyz
6. BRAND_IN_DOMAIN_NAME          sbi-kyc-update.com, paytmcashback.in

Rules that keep legitimate sites from being flagged:

* A URL on a brand's official domain (or its subdomains) is never flagged.
* Short brand keywords (< 5 letters, e.g. "sbi") only match whole words.
* Typo distance is only used for long keywords (configurable in brands.yaml).
* Brand names alone (checks 4–6) never reach MALICIOUS by themselves; only checks 1–3,
  where deception is structural, carry a minimum score (floor).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.analyzers.url_normalizer import ParsedURL, to_unicode_host
from app.analyzers.url_rules import Brand, UrlRules
from app.scoring.indicator import Indicator

_TOKEN_SPLIT_RE = re.compile(r"[.\-_]+")


@dataclass(frozen=True)
class BrandMatch:
    brand: str
    match_type: str  # official | lookalike | impersonation

    def to_dict(self) -> dict[str, str]:
        return {"brand": self.brand, "match_type": self.match_type}


def edit_distance(a: str, b: str) -> int:
    """Optimal-string-alignment distance: insertions, deletions, substitutions and
    swaps of two neighbouring letters each count as one edit ("bnak" -> "bank" = 1)."""
    rows, cols = len(a) + 1, len(b) + 1
    d = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        d[i][0] = i
    for j in range(cols):
        d[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def skeletons(text: str, rules: UrlRules) -> set[str]:
    """Versions of ``text`` with look-alike characters replaced by the letters they imitate."""
    base = "".join(rules.homoglyphs.get(ch, ch) for ch in text.lower())
    base = "".join(rules.ascii_substitutions.get(ch, ch) for ch in base)
    for fake, real in rules.multi_char_substitutions.items():
        base = base.replace(fake, real)
    # "1" imitates both "l" (paypa1) and "i" (1cici).
    return {base.replace("1", "l"), base.replace("1", "i")}


def _pattern_in(text: str, needle: str) -> bool:
    """True if ``needle`` appears in ``text`` bounded by start/end, dots or hyphens."""
    return re.search(rf"(^|[.\-]){re.escape(needle)}($|[.\-])", text) is not None


def _max_distance(keyword: str, rules: UrlRules) -> int:
    if len(keyword) >= rules.lookalike.min_length_for_distance_2:
        return 2
    if len(keyword) >= rules.lookalike.min_length_for_distance_1:
        return 1
    return 0


def _is_official(parsed: ParsedURL, rules: UrlRules) -> Brand | None:
    for domain, brand in rules.official_domains().items():
        if parsed.registrable_domain == domain or parsed.host == domain:
            return brand
        if parsed.host.endswith("." + domain):
            return brand
    return None


def _lookalike_keyword(name: str, brand: Brand, rules: UrlRules) -> str | None:
    """Return the brand keyword that ``name`` imitates, if any (name itself is not official)."""
    candidates = {name, *[t for t in _TOKEN_SPLIT_RE.split(name) if t]}
    for candidate in candidates:
        for keyword in brand.keywords:
            for skeleton in skeletons(candidate, rules):
                if skeleton == keyword and candidate != keyword:
                    return keyword  # character substitution (paypa1, аpple)
                limit = _max_distance(keyword, rules)
                if (
                    limit
                    and skeleton != keyword
                    and abs(len(skeleton) - len(keyword)) <= limit
                    and edit_distance(skeleton, keyword) <= limit
                ):
                    return keyword  # typo-squatting (hdfcbnak, faceboook)
    return None


def detect_lookalikes(
    parsed: ParsedURL, rules: UrlRules
) -> tuple[BrandMatch | None, list[Indicator]]:
    if parsed.ip is not None or parsed.is_dangerous_scheme:
        return None, []

    official = _is_official(parsed, rules)
    if official is not None:
        return BrandMatch(official.name, "official"), []

    indicators: list[Indicator] = []
    match: BrandMatch | None = None
    name_unicode = to_unicode_host(parsed.domain_name) if parsed.domain_name else ""
    name_tokens = [t for t in _TOKEN_SPLIT_RE.split(parsed.domain_name) if t]
    sub_tokens = [t for t in _TOKEN_SPLIT_RE.split(parsed.subdomain) if t]
    userinfo = (parsed.userinfo or "").lower()

    def add(indicator_id: str, brand: Brand, match_type: str) -> None:
        nonlocal match
        if all(existing.id != indicator_id for existing in indicators):
            indicators.append(Indicator(indicator_id, brand.name))
        if match is None or match_type == "lookalike":
            match = BrandMatch(brand.name, match_type)

    for brand in rules.brands:
        before = len(indicators)
        if any(_pattern_in(parsed.subdomain, d) for d in brand.official_domains):
            add("OFFICIAL_DOMAIN_IN_SUBDOMAIN", brand, "impersonation")
        if userinfo and any(d in userinfo for d in brand.official_domains):
            add("OFFICIAL_DOMAIN_IN_USERINFO", brand, "impersonation")

        lookalike = _lookalike_keyword(name_unicode, brand, rules)
        if lookalike:
            add("BRAND_LOOKALIKE", brand, "lookalike")
        elif parsed.domain_name in brand.keywords:
            add("BRAND_NAME_UNOFFICIAL_DOMAIN", brand, "impersonation")
        elif any(
            token in brand.keywords or any(len(k) >= 5 and k in token for k in brand.keywords)
            for token in name_tokens
        ):
            add("BRAND_IN_DOMAIN_NAME", brand, "impersonation")

        if len(indicators) == before and any(t in brand.keywords for t in sub_tokens):
            add("BRAND_IN_SUBDOMAIN", brand, "impersonation")

    return match, indicators
