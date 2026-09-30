"""/api/me: the signed-in user's settings and "delete my data"."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify

from app.schemas import UpdateSettingsRequest
from app.services.auth import require_auth, signed_in_user
from app.services.firebase_service import delete_auth_user
from app.utils.validation import parse_json_body

account_bp = Blueprint("account", __name__)


def _history():
    return current_app.extensions["qrguard.history"]


@account_bp.get("/me")
@require_auth
def get_me():
    return jsonify(_history().profile(signed_in_user()))


@account_bp.patch("/me")
@require_auth
def update_me():
    body = parse_json_body(UpdateSettingsRequest)
    return jsonify(_history().update_settings(signed_in_user(), body.save_history))


@account_bp.delete("/me")
@require_auth
def delete_me():
    """Deletes all saved scans, removes the uid from the user's reports, then the account."""
    user = signed_in_user()
    result = _history().delete_account_data(user)
    result["account_deleted"] = delete_auth_user(
        current_app.extensions["qrguard.firebase_app"], user.uid
    )
    return jsonify(result)
