"""Application configuration.

All settings come from environment variables (12-factor style). Nothing here is
specific to Render, so the same code runs locally, in Docker, on Render, Railway,
Fly.io or a VM.

``Config.from_env()`` takes the environment as an argument, which lets the tests
build a configuration without touching the real ``os.environ``.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from app.scoring.settings import ScoringSettings, load_scoring_settings

VALID_ENVIRONMENTS = ("development", "production", "testing")
VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
# off: never contact links | shorteners_only: follow known shorteners | all: follow every link
REDIRECT_MODES = ("off", "shorteners_only", "all")


class ConfigError(ValueError):
    """Raised at startup when an environment variable has an invalid value."""


def _get_int(env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int) -> int:
    raw = env.get(name, "").strip()
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value


def _get_choice(env: Mapping[str, str], name: str, default: str, choices: tuple[str, ...]) -> str:
    value = env.get(name, "").strip() or default
    if name == "LOG_LEVEL":
        value = value.upper()
    if value not in choices:
        raise ConfigError(f"{name} must be one of {', '.join(choices)}, got {value!r}")
    return value


def _get_ocr_languages(env: Mapping[str, str]) -> str:
    """Tesseract language codes such as "eng" or "eng+hin" (letters and "+" only)."""
    value = env.get("OCR_LANGUAGES", "").strip() or "eng"
    if not re.fullmatch(r"[a-z_]{3,}(?:\+[a-z_]{3,})*", value):
        raise ConfigError(f"OCR_LANGUAGES must look like 'eng' or 'eng+hin', got {value!r}")
    return value


def _get_list(env: Mapping[str, str], name: str, default: str) -> list[str]:
    raw = env.get(name, default)
    return [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    """Validated, read-only application settings."""

    app_env: str = "development"
    log_level: str = "INFO"
    allowed_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173"])
    max_upload_mb: int = 5
    max_json_kb: int = 64
    ratelimit_default: str = "60 per minute"
    ratelimit_analyze: str = "20 per minute;200 per day"
    ratelimit_storage_uri: str = "memory://"
    trust_proxy_hops: int = 0
    redirect_resolution: str = "shorteners_only"
    redirect_max_hops: int = 5
    redirect_timeout_seconds: int = 3
    redirect_total_timeout_seconds: int = 8
    ratelimit_screenshot: str = "6 per minute;60 per day"
    max_image_megapixels: int = 25
    tesseract_cmd: str = "tesseract"
    ocr_languages: str = "eng"
    ocr_timeout_seconds: int = 20
    ocr_max_concurrent: int = 2
    scoring: ScoringSettings = field(default_factory=load_scoring_settings)

    # ----- derived values -------------------------------------------------
    @property
    def debug(self) -> bool:
        return self.app_env == "development"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def max_content_length(self) -> int:
        """Hard cap on any request body (uploads included), in bytes."""
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_json_bytes(self) -> int:
        return self.max_json_kb * 1024

    # ----- construction -----------------------------------------------------
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Config:
        """Build a Config from environment variables, validating every value."""
        env = os.environ if env is None else env

        app_env = _get_choice(env, "APP_ENV", "development", VALID_ENVIRONMENTS)
        origins = _get_list(env, "ALLOWED_ORIGINS", "http://localhost:5173")
        if app_env == "production" and "*" in origins:
            raise ConfigError("ALLOWED_ORIGINS must list explicit origins in production, not '*'")
        for origin in origins:
            if origin != "*" and not origin.startswith(("http://", "https://")):
                raise ConfigError(f"ALLOWED_ORIGINS entry must start with http(s)://: {origin!r}")

        scoring_path = env.get("SCORING_CONFIG_PATH", "").strip() or None

        return cls(
            app_env=app_env,
            log_level=_get_choice(env, "LOG_LEVEL", "INFO", VALID_LOG_LEVELS),
            allowed_origins=origins,
            max_upload_mb=_get_int(env, "MAX_UPLOAD_MB", 5, 1, 20),
            max_json_kb=_get_int(env, "MAX_JSON_KB", 64, 1, 1024),
            ratelimit_default=env.get("RATELIMIT_DEFAULT", "").strip() or "60 per minute",
            ratelimit_analyze=env.get("RATELIMIT_ANALYZE", "").strip()
            or "20 per minute;200 per day",
            ratelimit_storage_uri=env.get("RATELIMIT_STORAGE_URI", "").strip() or "memory://",
            trust_proxy_hops=_get_int(env, "TRUST_PROXY_HOPS", 0, 0, 5),
            redirect_resolution=_get_choice(
                env, "REDIRECT_RESOLUTION", "shorteners_only", REDIRECT_MODES
            ),
            redirect_max_hops=_get_int(env, "REDIRECT_MAX_HOPS", 5, 0, 10),
            redirect_timeout_seconds=_get_int(env, "REDIRECT_TIMEOUT_SECONDS", 3, 1, 10),
            redirect_total_timeout_seconds=_get_int(
                env, "REDIRECT_TOTAL_TIMEOUT_SECONDS", 8, 1, 30
            ),
            ratelimit_screenshot=env.get("RATELIMIT_SCREENSHOT", "").strip()
            or "6 per minute;60 per day",
            max_image_megapixels=_get_int(env, "MAX_IMAGE_MEGAPIXELS", 25, 1, 50),
            tesseract_cmd=env.get("TESSERACT_CMD", "").strip() or "tesseract",
            ocr_languages=_get_ocr_languages(env),
            ocr_timeout_seconds=_get_int(env, "OCR_TIMEOUT_SECONDS", 20, 2, 60),
            ocr_max_concurrent=_get_int(env, "OCR_MAX_CONCURRENT", 2, 1, 8),
            scoring=load_scoring_settings(scoring_path),
        )
