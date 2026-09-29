import pytest

from app.config import Config, ConfigError


def test_defaults_are_valid():
    config = Config.from_env({})
    assert config.app_env == "development"
    assert config.max_content_length == 5 * 1024 * 1024
    assert config.allowed_origins == ["http://localhost:5173"]


def test_origins_are_split_and_trailing_slash_removed():
    config = Config.from_env({"ALLOWED_ORIGINS": "https://a.example/, http://localhost:5173"})
    assert config.allowed_origins == ["https://a.example", "http://localhost:5173"]


def test_wildcard_origin_rejected_in_production():
    with pytest.raises(ConfigError):
        Config.from_env({"APP_ENV": "production", "ALLOWED_ORIGINS": "*"})


def test_origin_without_scheme_rejected():
    with pytest.raises(ConfigError):
        Config.from_env({"ALLOWED_ORIGINS": "qrguard.vercel.app"})


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("APP_ENV", "staging"),
        ("LOG_LEVEL", "LOUD"),
        ("MAX_UPLOAD_MB", "abc"),
        ("MAX_UPLOAD_MB", "500"),
        ("TRUST_PROXY_HOPS", "-1"),
    ],
)
def test_invalid_values_fail_fast(name, value):
    with pytest.raises(ConfigError):
        Config.from_env({name: value})


def test_debug_only_in_development():
    assert Config.from_env({"APP_ENV": "development"}).debug is True
    assert (
        Config.from_env({"APP_ENV": "production", "ALLOWED_ORIGINS": "https://x.app"}).debug
        is False
    )
