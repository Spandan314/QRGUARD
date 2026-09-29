"""QRGUARD backend: Flask application factory.

``create_app()`` builds a fully configured Flask app. Using a factory (instead of
a global ``app = Flask(...)``) means tests can create apps with different
settings, and any WSGI server (gunicorn, waitress, a cloud platform) can import it.
"""

from __future__ import annotations

from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from app.analyzers.ocr import TesseractOcrEngine
from app.analyzers.redirect_resolver import RedirectSettings
from app.analyzers.scam_rules import load_scam_rules
from app.analyzers.url_rules import load_url_rules
from app.config import Config
from app.errors import register_error_handlers
from app.extensions import limiter
from app.logging_setup import configure_logging
from app.middleware import register_middleware
from app.routes import register_blueprints
from app.services.firebase_service import (
    DevTokenVerifier,
    FirebaseTokenVerifier,
    firestore_client,
    init_firebase_app,
)
from app.services.history_service import HistoryService
from app.services.history_store import FirestoreHistoryStore, MemoryHistoryStore
from app.services.message_analysis_service import MessageAnalysisService
from app.services.qr_analysis_service import QrAnalysisService
from app.services.screenshot_analysis_service import ScreenshotAnalysisService
from app.services.url_analysis_service import UrlAnalysisService
from app.threat_intelligence.factory import build_threat_intel
from app.threat_intelligence.feeds import update_feeds_command
from app.version import __version__

__all__ = ["create_app", "__version__"]


def _init_auth_and_history(app: Flask, config: Config) -> None:
    """Firebase auth + history (optional). Disabled mode: analysis works, history answers 503."""
    firebase_app = init_firebase_app(config)
    app.extensions["qrguard.firebase_app"] = firebase_app
    verifier = None
    if config.auth_dev_tokens:
        verifier = DevTokenVerifier()
    elif firebase_app is not None:
        verifier = FirebaseTokenVerifier(firebase_app)
    app.extensions["qrguard.token_verifier"] = verifier

    store = None
    if config.history_store == "memory":
        store = MemoryHistoryStore()
    elif config.history_store == "firestore":
        store = FirestoreHistoryStore(firestore_client(config, firebase_app))
    if store is not None and verifier is None:
        app.logger.warning("History store configured but no way to sign in; history is disabled")
        store = None
    app.extensions["qrguard.history"] = HistoryService(store, config.history_retention_days)


def create_app(config: Config | None = None) -> Flask:
    """Create the Flask app. Pass a ``Config`` in tests; otherwise env vars are used."""
    config = config or Config.from_env()

    configure_logging(config.log_level)

    app = Flask(__name__)
    app.json.sort_keys = False  # keep responses in their logical order (score first)
    app.config.update(
        QRGUARD=config,  # our validated settings object, read via current_app.config["QRGUARD"]
        DEBUG=config.debug,
        TESTING=config.app_env == "testing",
        MAX_CONTENT_LENGTH=config.max_content_length,
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

    # Analysis services are created once per app (rule files are validated at startup).
    url_rules = load_url_rules()
    # Local feeds are on by default; external providers only when their API key is set.
    threat_intel = build_threat_intel(config, url_rules)
    url_service = UrlAnalysisService(
        rules=url_rules,
        scoring=config.scoring,
        threat_intel=threat_intel,
        redirect_mode=config.redirect_resolution,
        redirect_settings=RedirectSettings(
            max_hops=config.redirect_max_hops,
            request_timeout=config.redirect_timeout_seconds,
            total_timeout=config.redirect_total_timeout_seconds,
        ),
    )
    app.extensions["qrguard.url_analysis"] = url_service
    message_service = MessageAnalysisService(
        rules=load_scam_rules(url_rules), url_service=url_service
    )
    app.extensions["qrguard.message_analysis"] = message_service
    qr_service = QrAnalysisService(
        url_service=url_service,
        message_service=message_service,
        max_bytes=config.max_content_length,
        max_pixels=config.max_image_megapixels * 1_000_000,
    )
    app.extensions["qrguard.qr_analysis"] = qr_service
    app.extensions["qrguard.screenshot_analysis"] = ScreenshotAnalysisService(
        message_service=message_service,
        qr_service=qr_service,
        ocr_engine=TesseractOcrEngine(
            command=config.tesseract_cmd,
            languages=config.ocr_languages,
            timeout=config.ocr_timeout_seconds,
            max_concurrent=config.ocr_max_concurrent,
        ),
        max_bytes=config.max_content_length,
        max_pixels=config.max_image_megapixels * 1_000_000,
    )

    _init_auth_and_history(app, config)

    register_middleware(app)
    register_error_handlers(app)
    register_blueprints(app)

    app.logger.info("QRGUARD backend started (env=%s, version=%s)", config.app_env, __version__)
    app.cli.add_command(update_feeds_command)
    return app
