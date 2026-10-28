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


def test_production_and_preview_origins_are_kept_as_listed():
    value = "https://qrguard.vercel.app, https://qrguard-git-airlock-redesign-develop-qrguard.vercel.app/"
    config = Config.from_env({"APP_ENV": "production", "ALLOWED_ORIGINS": value})
    assert config.allowed_origins == [
        "https://qrguard.vercel.app",
        "https://qrguard-git-airlock-redesign-develop-qrguard.vercel.app",
    ]


@pytest.mark.parametrize("env", ["development", "production"])
@pytest.mark.parametrize(
    "origin",
    [
        "https://*.vercel.app",  # flask-cors would treat these as regular expressions
        r"https://.*\.vercel\.app",
        "^https://qrguard.vercel.app$",
        "https://qrguard.vercel.app/app",  # an origin has no path
        "https://qrguard.vercel.app?x=1",
        "https://user@qrguard.vercel.app",
        '"https://qrguard.vercel.app"',  # quoted in the dashboard
    ],
)
def test_patterns_and_non_origins_rejected(env, origin):
    with pytest.raises(ConfigError, match="exact origins"):
        Config.from_env({"APP_ENV": env, "ALLOWED_ORIGINS": f"https://qrguard.vercel.app,{origin}"})


@pytest.mark.parametrize(
    "origin", ["http://localhost:5173", "http://127.0.0.1:8000", "https://Web.QRGuard.test:8443"]
)
def test_exact_origins_accepted(origin):
    assert Config.from_env({"ALLOWED_ORIGINS": origin}).allowed_origins == [origin]


def test_wildcard_still_allowed_outside_production():
    assert Config.from_env({"APP_ENV": "development", "ALLOWED_ORIGINS": "*"}).allowed_origins == [
        "*"
    ]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("APP_ENV", "staging"),
        ("LOG_LEVEL", "LOUD"),
        ("MAX_UPLOAD_MB", "abc"),
        ("MAX_UPLOAD_MB", "500"),
        ("TRUST_PROXY_HOPS", "-1"),
        ("REDIRECT_MAX_CONCURRENT", "0"),
        ("REDIRECT_MAX_CONCURRENT", "17"),
        ("REDIRECT_RESOLUTION", "ALL"),
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
