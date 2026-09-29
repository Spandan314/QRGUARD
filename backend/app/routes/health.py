"""GET /api/health: liveness and component status.

Used by Render's health check, by the apps' "backend status" indicator and by
the team to confirm a deployment. It reports only components that actually exist,
and never reveals secrets, versions of dependencies or internal paths.
"""

from __future__ import annotations

import shutil
from datetime import UTC, datetime

from flask import Blueprint, current_app, jsonify

from app.extensions import limiter
from app.version import __version__

health_bp = Blueprint("health", __name__)


def _ocr_status() -> str:
    # Tesseract is a system program (installed in the Docker image).
    # The OCR module is built in Phase 3; this check proves the binary is present early.
    return "available" if shutil.which("tesseract") else "not_installed"


@health_bp.get("/health")
@limiter.exempt
def health():
    config = current_app.config["QRGUARD"]
    return jsonify(
        {
            "status": "ok",
            "service": "qrguard-backend",
            "engine_version": __version__,
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
            "components": {
                "api": "ok",
                "scoring_config": {
                    "status": "loaded",
                    "version": config.scoring.version,
                    "thresholds": config.scoring.thresholds.model_dump(),
                },
                "ocr_engine": _ocr_status(),
            },
        }
    )
