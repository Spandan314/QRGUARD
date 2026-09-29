from app.analyzers.url_features import extract_url_features
from app.analyzers.url_normalizer import normalize_url
from app.analyzers.url_rules import load_url_rules

RULES = load_url_rules()


def analyze(url: str):
    features, indicators = extract_url_features(normalize_url(url, RULES), RULES)
    return features, [i.id for i in indicators]


def test_clean_https_url_has_no_warning_indicators():
    features, ids = analyze("https://www.example.com/about")
    assert ids == []
    assert features["uses_https"] and not features["is_trusted_domain"]


def test_trusted_domain():
    features, ids = analyze("https://en.wikipedia.org/wiki/QR_code")
    assert ids == ["TRUSTED_DOMAIN"] and features["is_trusted_domain"]


def test_government_suffix_entry_trusts_subdomains():
    assert "TRUSTED_DOMAIN" in analyze("https://www.incometax.gov.in/")[1]


def test_http():
    assert "URL_NO_HTTPS" in analyze("http://example.com/")[1]


def test_ip_address_host():
    features, ids = analyze("http://8.8.4.4/login")
    assert "URL_IP_HOST" in ids and features["is_ip_address"]
    assert "URL_OBFUSCATED_IP" not in ids


def test_disguised_private_ip():
    ids = analyze("http://0x7f000001/")[1]
    assert {"URL_IP_HOST", "URL_OBFUSCATED_IP", "URL_PRIVATE_NETWORK_HOST"} <= set(ids)


def test_local_hostnames_are_private():
    assert "URL_PRIVATE_NETWORK_HOST" in analyze("http://printer.local/")[1]
    assert "URL_PRIVATE_NETWORK_HOST" in analyze("http://intranet/")[1]


def test_long_and_very_long_urls():
    assert "URL_LONG" in analyze("https://example.com/" + "a" * 100)[1]
    ids = analyze("https://example.com/" + "a" * 250)[1]
    assert "URL_VERY_LONG" in ids and "URL_LONG" not in ids


def test_at_symbol_userinfo():
    features, ids = analyze("https://secure-login@example.com/")
    assert "URL_USERINFO_AT" in ids and features["has_userinfo"]


def test_excessive_subdomains_ignore_www():
    assert "URL_MANY_SUBDOMAINS" in analyze("https://a.b.c.d.example.com/")[1]
    assert "URL_MANY_SUBDOMAINS" not in analyze("https://www.a.b.example.com/")[1]


def test_phishing_keywords_are_whole_words_or_long_parts():
    features, ids = analyze("https://example.com/secure/account-verify?pin=1")
    assert ids.count("URL_PHISHING_KEYWORD") == 3  # capped at 3 indicators
    assert {"secure", "verify"} <= set(features["phishing_keywords"])
    assert (
        analyze("https://spinner.example.com/")[0]["phishing_keywords"] == []
    )  # "pin" inside word


def test_shortener():
    features, ids = analyze("https://bit.ly/3abc")
    assert "URL_SHORTENER" in ids and features["is_shortener"]


def test_punycode_and_mixed_script():
    ids = analyze("https://xn--pypal-4ve.com/")[1]  # "pаypal" with Cyrillic а
    assert "URL_PUNYCODE" in ids and "URL_MIXED_SCRIPT" in ids


def test_genuine_idn_is_punycode_but_not_mixed_script():
    ids = analyze("https://bücher.de/")[1]
    assert "URL_PUNYCODE" in ids and "URL_MIXED_SCRIPT" not in ids


def test_suspicious_tld_port_hyphens_executable_and_user_content():
    assert "URL_SUSPICIOUS_TLD" in analyze("https://example.xyz/")[1]
    assert "URL_NONSTANDARD_PORT" in analyze("https://example.com:8443/")[1]
    assert "URL_MANY_HYPHENS" in analyze("https://secure-login-bank-update-now.com/")[1]
    assert "URL_EXECUTABLE_DOWNLOAD" in analyze("https://example.com/app/update.APK")[1]
    ids = analyze("https://docs.google.com/forms/d/abc")[1]
    assert "URL_USER_CONTENT_HOST" in ids and "TRUSTED_DOMAIN" not in ids


def test_encoding_embedded_url_backslash_and_special_chars():
    assert "URL_ENCODED_CHARS" in analyze("https://example.com/%6c%6f%67%69%6e")[1]
    assert "URL_EMBEDDED_URL" in analyze("https://example.com/r?u=https%3A%2F%2Fevil.xyz")[1]
    assert "URL_BACKSLASH" in analyze("https://example.com\\login")[1]
    assert "URL_SPECIAL_CHARS" in analyze("https://example.com/~-_=&!;$+*'()-_=&!;$+*'()")[1]


def test_scheme_assumed_is_informational():
    assert analyze("example.com")[1] == ["URL_SCHEME_ASSUMED"]
