"""Flask extensions, created once and attached to the app in ``create_app``.

Keeping them here (instead of inside ``create_app``) lets route modules use the
``@limiter.limit`` decorator without circular imports.
"""

from flask import current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# The client IP is the rate-limit key. Behind Render's proxy the real IP is only
# correct because ProxyFix is enabled via TRUST_PROXY_HOPS (see app/__init__.py).
# Phase 7 changes the key to the Firebase uid for signed-in users.
#
# Limits are given as functions that read the app config at request time. That keeps
# every setting in Config (one place) and works even if several apps are created
# in the same process (as the tests do).


def default_rate_limit() -> str:
    """Rate limit applied to every route that has no specific limit."""
    return current_app.config["QRGUARD"].ratelimit_default


def analyze_rate_limit() -> str:
    """Rate limit string for the analysis endpoints, read from config at request time."""
    return current_app.config["QRGUARD"].ratelimit_analyze


limiter = Limiter(key_func=get_remote_address, default_limits=[default_rate_limit])
