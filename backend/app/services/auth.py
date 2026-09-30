"""Request authentication: `Authorization: Bearer <Firebase ID token>`.

    @optional_auth  analysis: works without a token; a token that is present must be valid
    @require_auth   history, reports, account: 401 without a valid token
    @require_admin  admin dashboard: 403 unless the token has the custom claim admin=true

The token is verified at most once per request (the rate limiter also needs the uid, and it runs
before the view), and the result is cached on `flask.g`. Tokens are never logged.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from flask import current_app, g, request

from app.errors import APIError
from app.services.firebase_service import AuthUnavailableError, AuthUser, InvalidTokenError

F = TypeVar("F", bound=Callable[..., Any])

_UNRESOLVED = object()
MAX_TOKEN_CHARS = 4096


def _resolve() -> tuple[AuthUser | None, str | None]:
    """(user, problem) where problem is None, "missing", "invalid" or "unavailable"."""
    cached = getattr(g, "_auth", _UNRESOLVED)
    if cached is not _UNRESOLVED:
        return cached
    header = request.headers.get("Authorization", "")
    result: tuple[AuthUser | None, str | None]
    if not header:
        result = (None, "missing")
    else:
        scheme, _, token = header.partition(" ")
        token = token.strip()
        verifier = current_app.extensions.get("qrguard.token_verifier")
        if scheme.lower() != "bearer" or not token or len(token) > MAX_TOKEN_CHARS:
            result = (None, "invalid")
        elif verifier is None:
            result = (None, "unavailable")
        else:
            try:
                result = (verifier.verify(token), None)
            except InvalidTokenError:
                result = (None, "invalid")
            except AuthUnavailableError:
                result = (None, "unavailable")
    g._auth = result
    return result


def current_user() -> AuthUser | None:
    return _resolve()[0]


def optional_auth(view: F) -> F:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _, problem = _resolve()
        if problem == "invalid":
            raise APIError(401, "INVALID_TOKEN", "Your session has expired. Please sign in again.")
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def require_auth(view: F) -> F:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not current_app.extensions["qrguard.history"].enabled:
            raise APIError(503, "SERVICE_UNAVAILABLE", "History is not available on this server.")
        user, problem = _resolve()
        if problem == "missing":
            raise APIError(401, "AUTH_REQUIRED", "Please sign in to use this feature.")
        if problem == "invalid":
            raise APIError(401, "INVALID_TOKEN", "Your session has expired. Please sign in again.")
        if problem == "unavailable" or user is None:
            raise APIError(503, "SERVICE_UNAVAILABLE", "Sign-in is temporarily unavailable.")
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def require_admin(view: F) -> F:
    @require_auth
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        user = current_user()
        if user is None or not user.admin:
            raise APIError(403, "FORBIDDEN", "Administrator access is required.")
        return view(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def signed_in_user() -> AuthUser:
    """For views behind @require_auth."""
    user = current_user()
    if user is None:  # pragma: no cover - guaranteed by @require_auth
        raise APIError(401, "AUTH_REQUIRED", "Please sign in to use this feature.")
    return user
