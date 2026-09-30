"""Firebase Admin SDK wrapper: ID-token verification and the Firestore client.

Everything is optional. Without FIREBASE_PROJECT_ID the app runs in "disabled" mode: analysis works
for everyone, and sign-in / history answer 503 SERVICE_UNAVAILABLE. Credentials come only from the
environment (a service-account file path or its JSON); they are never logged.

For local demos and automated API tests (no Firebase project), AUTH_DEV_TOKENS=true accepts tokens
of the form "dev-<uid>" (and "dev-admin-<uid>" for an admin). Config refuses it in production.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Protocol

import click
from flask import current_app
from flask.cli import with_appcontext

from app.config import Config

logger = logging.getLogger("qrguard.auth")

_DEV_TOKEN_RE = re.compile(r"^dev-(admin-)?([A-Za-z0-9_-]{3,64})$")


@dataclass(frozen=True)
class AuthUser:
    uid: str
    is_anonymous: bool = False
    admin: bool = False


class InvalidTokenError(Exception):
    """The token is malformed, expired, revoked or not issued for this project."""


class AuthUnavailableError(Exception):
    """Tokens cannot be checked right now (e.g. Google's public keys could not be fetched)."""


class TokenVerifier(Protocol):
    def verify(self, token: str) -> AuthUser: ...


class DevTokenVerifier:
    """Accepts "dev-<uid>" / "dev-admin-<uid>" (development and testing only)."""

    def verify(self, token: str) -> AuthUser:
        match = _DEV_TOKEN_RE.match(token)
        if not match:
            raise InvalidTokenError
        return AuthUser(uid=f"dev-{match.group(2)}", admin=bool(match.group(1)))


class FirebaseTokenVerifier:
    """Verifies Firebase ID tokens (signature, expiry, audience = our project, issuer)."""

    def __init__(self, app: Any) -> None:
        self._app = app

    def verify(self, token: str) -> AuthUser:
        from firebase_admin import auth

        try:
            claims = auth.verify_id_token(token, app=self._app)
        except auth.CertificateFetchError as exc:
            raise AuthUnavailableError from exc
        except (auth.InvalidIdTokenError, auth.UserDisabledError, ValueError) as exc:
            raise InvalidTokenError from exc
        provider = (claims.get("firebase") or {}).get("sign_in_provider")
        return AuthUser(
            uid=str(claims["uid"]),
            is_anonymous=provider == "anonymous",
            admin=claims.get("admin") is True,  # custom claim, set only by an admin script
        )


def _credentials(config: Config) -> Any:
    from firebase_admin import credentials

    if config.firebase_credentials_json:
        try:
            return credentials.Certificate(json.loads(config.firebase_credentials_json))
        except (ValueError, KeyError) as exc:
            raise ValueError(
                "FIREBASE_CREDENTIALS_JSON is not a valid service-account key"
            ) from exc
    if config.firebase_credentials_file:
        return credentials.Certificate(config.firebase_credentials_file)
    return None  # Application Default Credentials (e.g. on Google Cloud) or the emulator


def init_firebase_app(config: Config) -> Any | None:
    """Initialise a named Firebase app for this Flask app, or return None if not configured."""
    if not config.firebase_project_id:
        return None
    import firebase_admin

    name = f"qrguard-{id(config)}"
    try:
        return firebase_admin.get_app(name)
    except ValueError:
        pass
    options = {"projectId": config.firebase_project_id}
    cred = _credentials(config)
    if cred is not None:
        return firebase_admin.initialize_app(cred, options, name=name)
    return firebase_admin.initialize_app(options=options, name=name)


def firestore_client(config: Config, app: Any) -> Any:
    """Firestore client: the local emulator when FIRESTORE_EMULATOR_HOST is set, else Firebase."""
    if os.environ.get("FIRESTORE_EMULATOR_HOST"):
        from google.auth.credentials import AnonymousCredentials
        from google.cloud import firestore

        return firestore.Client(
            project=config.firebase_project_id, credentials=AnonymousCredentials()
        )
    from firebase_admin import firestore as admin_firestore

    return admin_firestore.client(app)


def delete_auth_user(app: Any, uid: str) -> bool:
    """Delete the Firebase Auth account (used by "delete my data"). False if not possible."""
    if app is None:
        return False
    from firebase_admin import auth

    try:
        auth.delete_user(uid, app=app)
        return True
    except auth.UserNotFoundError:
        return True
    except Exception:  # noqa: BLE001 - never fail the data deletion because of the account
        logger.warning("auth user could not be deleted", extra={"event": "auth_delete_failed"})
        return False


@click.command("set-admin")
@click.argument("uid")
@click.option("--revoke", is_flag=True, help="Remove the admin claim instead of granting it.")
@with_appcontext
def set_admin_command(uid: str, revoke: bool) -> None:
    """`flask --app wsgi set-admin <uid> [--revoke]`: grant or remove the "admin" custom claim.

    Other custom claims are kept. The user must sign in again (or refresh the ID token) before
    the change is visible to the API.
    """
    from firebase_admin import auth

    app = current_app.extensions.get("qrguard.firebase_app")
    if app is None:
        raise click.ClickException("Firebase is not configured (set FIREBASE_PROJECT_ID)")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", uid):
        raise click.ClickException("That does not look like a Firebase uid")
    try:
        user = auth.get_user(uid, app=app)
    except auth.UserNotFoundError:
        raise click.ClickException(f"No user with uid {uid}") from None
    claims = dict(user.custom_claims or {})
    if revoke:
        claims.pop("admin", None)
    else:
        claims["admin"] = True
    auth.set_custom_user_claims(uid, claims or None, app=app)
    click.echo(f"{'Removed' if revoke else 'Granted'} admin for {uid}.")
