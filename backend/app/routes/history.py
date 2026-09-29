"""/api/history: the signed-in user's scan history (Firebase, Phase 7).

These routes will require a Firebase ID token. Until Phase 7 they return 501 so
clients can already handle the response shape.
"""

from __future__ import annotations

from flask import Blueprint

from app.errors import APIError

history_bp = Blueprint("history", __name__)


def _not_implemented() -> APIError:
    return APIError(501, "NOT_IMPLEMENTED", "History is not implemented yet (planned: Phase 7).")


@history_bp.get("/history")
def list_history():
    raise _not_implemented()


@history_bp.delete("/history")
def delete_all_history():
    raise _not_implemented()


@history_bp.delete("/history/<string:scan_id>")
def delete_history_item(scan_id: str):
    raise _not_implemented()
