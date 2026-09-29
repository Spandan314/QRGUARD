"""QRGUARD backend: Flask application factory.

``create_app()`` builds a fully configured Flask app. Using a factory (instead of
a global ``app = Flask(...)``) means tests can create apps with different
settings, and any WSGI server (gunicorn, waitress, a cloud platform) can import it.
"""

from __future__ import annotations

from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config
from app.errors import register_error_handlers
from app.extensions import limiter
from app.logging_setup import configure_logging
from app.middleware import register_middleware
from app.routes import register_blueprints
from app.version import __version__

__all__ = ["create_app", "__version__"]


def create_app(config: Config | None = None) -> Flask:
    """Create the Flask app. Pass a ``Config`` in tests; otherwise env vars are used."""
    config = config or Config.from_env()

    configure_logging(config.log_level)

    app = Flask(__name__)
    app.config.update(
        QRGUARD=config,  # our validated settings object, read via current_app.config["QRGUARD"]
        DEBUG=config.debug,
        TESTING=config.app_env == "testing",
        MAX_CONTENT_LENGTH=config.max_content_length,
        JSON_SORT_KEYS=False,
        RATELIMIT_STORAGE_URI=config.ratelimit_storage_uri,
        RATELIMIT_HEADERS_ENABLED=True,
    )

    # Behind a reverse proxy (Render, Railway, Nginx...) trust X-Forwarded-For/Proto
    # for exactly the configured number of hops, so rate limits see the real client IP.
    if config.trust_proxy_hops:
        hops = config.trust_proxy_hops
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=hops)  # type: ignore[method-assign]

    CORS(
        app,
        resources={r"/api/*": {"origins": config.allowed_origins}},
        methods=["GET", "POST", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID", "Retry-After"],
        supports_credentials=False,  # we use Authorization headers, not cookies
        max_age=600,
    )
    limiter.init_app(app)

    register_middleware(app)
    register_error_handlers(app)
    register_blueprints(app)

    app.logger.info("QRGUARD backend started (env=%s, version=%s)", config.app_env, __version__)
    return app
