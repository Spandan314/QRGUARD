import pytest

from app.analyzers.lookalike import detect_lookalikes, edit_distance
from app.analyzers.url_normalizer import normalize_url
from app.analyzers.url_rules import load_url_rules

RULES = load_url_rules()


def check(url: str):
    match, indicators = detect_lookalikes(normalize_url(url, RULES), RULES)
    return match, [i.id for i in indicators]


@pytest.mark.parametrize(
    "url",
    [
        "https://www.onlinesbi.sbi/",
        "https://sbi.co.in/web/personal-banking",
        "https://netbanking.hdfcbank.com/netbanking/",
        "https://www.sbicard.com/",
        "https://pay.google.com/",
        "https://www.amazon.in/deals",
    ],
)
def test_official_brand_domains_are_never_flagged(url):
    match, ids = check(url)
    assert ids == [] and match.match_type == "official"


@pytest.mark.parametrize(
    "url",
    [
        "https://en.wikipedia.org/",
        "https://sbilling.com/",
        "https://amazing.com/",
        "https://apply.com/",
        "https://example.com/sbi",
    ],
)
def test_unrelated_domains_are_not_flagged(url):
    assert check(url) == (None, [])


@pytest.mark.parametrize(
    ("url", "brand"),
    [
        ("https://paypa1.com/", "PayPal"),  # 1 -> l
        ("https://g00gle.com/", "Google"),  # 0 -> o
        ("https://hdfcbnak.com/", "HDFC Bank"),  # swapped letters
        ("https://faceboook.com/", "Meta (Facebook / Instagram / WhatsApp)"),  # extra letter
        ("https://xn--80ak6aa92e.com/", "Apple"),  # all-Cyrillic "аррӏе"
        ("https://secure-paypa1.com/login", "PayPal"),  # lookalike inside a hyphenated name
        ("https://rnicrosoft.com/", "Microsoft"),  # rn -> m
    ],
)
def test_lookalikes(url, brand):
    match, ids = check(url)
    assert "BRAND_LOOKALIKE" in ids
    assert match.brand == brand and match.match_type == "lookalike"


def test_official_domain_used_as_subdomain():
    assert check("http://sbi.co.in.kyc-verify.xyz/")[1] == ["OFFICIAL_DOMAIN_IN_SUBDOMAIN"]
    assert "OFFICIAL_DOMAIN_IN_SUBDOMAIN" in check("https://paypal.com-secure.evil.xyz/")[1]


def test_official_domain_before_at_sign():
    assert "OFFICIAL_DOMAIN_IN_USERINFO" in check("https://www.sbi.co.in@evil.xyz/")[1]


def test_brand_in_subdomain_of_other_site():
    assert check("https://paytm.secure-login.xyz/")[1] == ["BRAND_IN_SUBDOMAIN"]


def test_brand_name_on_unofficial_domain_ending():
    assert check("https://paypal.xyz/")[1] == ["BRAND_NAME_UNOFFICIAL_DOMAIN"]


@pytest.mark.parametrize("url", ["https://sbi-kyc-update.com/", "https://paytmcashback.in/"])
def test_brand_combined_with_other_words(url):
    assert check(url)[1] == ["BRAND_IN_DOMAIN_NAME"]


def test_ip_hosts_are_skipped():
    assert check("http://8.8.8.8/paypal") == (None, [])


@pytest.mark.parametrize(
    ("a", "b", "distance"),
    [
        ("bank", "bank", 0),
        ("bnak", "bank", 1),
        ("hdfcbank", "hdfcbnk", 1),
        ("abc", "xyz", 3),
        ("", "abc", 3),
    ],
)
def test_edit_distance(a, b, distance):
    assert edit_distance(a, b) == distance
