"""API blueprints. Each module owns one group of endpoints under /api."""

from flask import Flask

from app.routes.analyze import analyze_bp
from app.routes.generate import generate_bp
from app.routes.health import health_bp
from app.routes.history import history_bp


def register_blueprints(app: Flask) -> None:
    for blueprint in (health_bp, analyze_bp, generate_bp, history_bp):
        app.register_blueprint(blueprint, url_prefix="/api")
