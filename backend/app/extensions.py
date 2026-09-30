"""Flask extensions, created once and attached to the app in ``create_app``.

Keeping them here (instead of inside ``create_app``) lets route modules use the
``@limiter.limit`` decorator without circular imports.
"""

from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Rate-limit key: the Firebase uid for signed-in users, otherwise the client IP. Behind Render's
# proxy the IP is only correct because ProxyFix is enabled via TRUST_PROXY_HOPS
# (see app/__init__.py). An invalid token falls back to the IP key (the view then answers 401).
#
# Limits are given as functions that read the app config at request time. That keeps
# every setting in Config (one place) and works even if several apps are created
# in the same process (as the tests do).


def rate_limit_key() -> str:
    from app.services.auth import current_user

    user = current_user()
    return f"uid:{user.uid}" if user else get_remote_address()


def default_rate_limit() -> str:
    """Rate limit applied to every route that has no specific limit."""
    return current_app.config["QRGUARD"].ratelimit_default


def analyze_rate_limit() -> str:
    """Analysis limit: higher for signed-in users (per uid) than for anonymous callers (per IP)."""
    from app.services.auth import current_user

    config = current_app.config["QRGUARD"]
    return config.ratelimit_analyze_auth if current_user() else config.ratelimit_analyze


def screenshot_rate_limit() -> str:
    """Extra, stricter limit for OCR (CPU-heavy), on top of the analysis limit."""
    return current_app.config["QRGUARD"].ratelimit_screenshot


def reports_rate_limit() -> str:
    return current_app.config["QRGUARD"].ratelimit_reports


limiter = Limiter(key_func=rate_limit_key, default_limits=[default_rate_limit])
