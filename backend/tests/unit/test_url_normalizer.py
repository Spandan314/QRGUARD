import ipaddress

import pytest

from app.analyzers.url_normalizer import URLValidationError, normalize_url
from app.analyzers.url_rules import load_url_rules

RULES = load_url_rules()


def norm(url: str):
    return normalize_url(url, RULES)


def test_normal_https_url_is_canonicalised():
    p = norm("  HTTPS://WWW.Example.COM:443/Path?q=1#section  ")
    assert p.normalized == "https://www.example.com/Path?q=1"  # host lowercased, port+fragment gone
    assert (p.scheme, p.host, p.port) == ("https", "www.example.com", None)
    assert (p.subdomain, p.domain_name, p.suffix) == ("www", "example", "com")
    assert p.registrable_domain == "example.com"


def test_empty_path_becomes_slash_and_trailing_dot_removed():
    assert norm("https://example.com.").normalized == "https://example.com/"


def test_missing_scheme_is_assumed_https():
    p = norm("example.co.in/login")
    assert p.scheme_assumed and p.scheme == "https"
    assert p.registrable_domain == "example.co.in"


def test_host_with_port_is_not_mistaken_for_scheme():
    p = norm("localhost:8080/admin")
    assert p.host == "localhost" and p.port == 8080 and p.scheme_assumed


def test_password_in_userinfo_is_masked():
    p = norm("https://user:secret@example.com/")
    assert "secret" not in p.normalized
    assert p.userinfo == "user:***"


def test_backslashes_are_treated_like_browsers_do():
    p = norm("https://example.com\\evil.com\\login")
    assert p.had_backslash and p.host == "example.com"


def test_unicode_host_is_converted_to_punycode():
    p = norm("https://bücher.de/")
    assert p.host == "xn--bcher-kva.de"
    assert p.host_unicode == "bücher.de"


def test_punycode_host_is_decoded_for_display():
    assert norm("https://xn--80ak6aa92e.com/").host_unicode == "аррӏе.com"


def test_psl_private_suffix_keeps_user_site_separate():
    assert norm("https://evil.github.io/x").registrable_domain == "evil.github.io"


def test_host_without_public_suffix_uses_last_two_labels():
    p = norm("http://sbi-kyc.example/login")
    assert p.registrable_domain == "sbi-kyc.example" and not p.has_public_suffix


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1/", "127.0.0.1"),
        ("http://[::1]/", "::1"),
        ("http://2130706433/", "127.0.0.1"),  # decimal
        ("http://0x7f.0.0.1/", "127.0.0.1"),  # hex
        ("http://0177.0.0.1/", "127.0.0.1"),  # octal
        ("http://127.1/", "127.0.0.1"),  # short form
    ],
)
def test_ip_literals_including_disguised_forms(url, expected):
    p = norm(url)
    assert p.ip == ipaddress.ip_address(expected)
    assert p.registrable_domain == expected


def test_disguised_ip_is_flagged():
    assert norm("http://0x7f000001/").ip_disguised
    assert not norm("http://127.0.0.1/").ip_disguised


@pytest.mark.parametrize("url", ["javascript:alert(1)", "JavaScript:void(0)", "data:text/html,hi"])
def test_dangerous_schemes_are_flagged_not_parsed(url):
    p = norm(url)
    assert p.is_dangerous_scheme and p.host == ""


@pytest.mark.parametrize(
    ("url", "code"),
    [
        ("", "EMPTY_URL"),
        ("   ", "EMPTY_URL"),
        ("http://", "INVALID_URL"),
        ("https://exa mple.com", "INVALID_URL"),
        ("https://example.com/\x00", "INVALID_URL"),
        ("http://example.com:99999/", "INVALID_URL"),
        ("http://exa$mple.com/", "INVALID_URL"),
        ("http://[::1", "INVALID_URL"),  # broken IPv6 brackets used to cause a 500
        ("https://[bad]/", "INVALID_URL"),
        ("http://a..b.com/", "INVALID_URL"),
        ("ftp://files.example.com/", "UNSUPPORTED_PROTOCOL"),
        ("mailto:someone@example.com", "UNSUPPORTED_PROTOCOL"),
        ("upi://pay?pa=x@upi", "UNSUPPORTED_PROTOCOL"),
    ],
)
def test_invalid_inputs(url, code):
    with pytest.raises(URLValidationError) as err:
        norm(url)
    assert err.value.code == code


def test_tabs_and_newlines_are_removed():
    assert norm("https://exam\tple.com/\n").host == "example.com"
