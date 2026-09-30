"""Firebase token verification and app setup (the Firebase SDK is faked; no network)."""

import pytest
from firebase_admin import auth

from app.config import Config
from app.services import firebase_service as fs


def test_dev_tokens():
    verifier = fs.DevTokenVerifier()
    assert verifier.verify("dev-alice") == fs.AuthUser(uid="dev-alice")
    assert verifier.verify("dev-admin-root") == fs.AuthUser(uid="dev-root", admin=True)
    for bad in ("alice", "dev-", "dev-a", "dev-alice bob", "dev-" + "x" * 65):
        with pytest.raises(fs.InvalidTokenError):
            verifier.verify(bad)


def test_firebase_verifier_maps_claims(monkeypatch):
    claims = {"uid": "u1", "firebase": {"sign_in_provider": "anonymous"}, "admin": True}
    monkeypatch.setattr(auth, "verify_id_token", lambda token, app: claims)
    user = fs.FirebaseTokenVerifier(app=object()).verify("t")
    assert user == fs.AuthUser(uid="u1", is_anonymous=True, admin=True)


def test_admin_claim_must_be_exactly_true(monkeypatch):
    monkeypatch.setattr(auth, "verify_id_token", lambda token, app: {"uid": "u", "admin": "true"})
    assert fs.FirebaseTokenVerifier(app=object()).verify("t").admin is False


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (auth.ExpiredIdTokenError("expired", cause=None), fs.InvalidTokenError),
        (auth.RevokedIdTokenError("revoked"), fs.InvalidTokenError),
        (auth.InvalidIdTokenError("bad"), fs.InvalidTokenError),
        (ValueError("malformed"), fs.InvalidTokenError),
        (auth.CertificateFetchError("no keys", cause=None), fs.AuthUnavailableError),
    ],
)
def test_firebase_verifier_errors(monkeypatch, error, expected):
    def fail(token, app):
        raise error

    monkeypatch.setattr(auth, "verify_id_token", fail)
    with pytest.raises(expected):
        fs.FirebaseTokenVerifier(app=object()).verify("t")


def test_no_project_means_no_firebase_app():
    assert fs.init_firebase_app(Config.from_env({})) is None
    assert fs.delete_auth_user(None, "u") is False


def test_app_without_credentials_and_reuse():
    config = Config.from_env({"FIREBASE_PROJECT_ID": "qrguard-test", "HISTORY_STORE": "off"})
    first = fs.init_firebase_app(config)
    assert first is fs.init_firebase_app(config)
    assert first.project_id == "qrguard-test"


def test_invalid_credentials_json_is_reported_without_its_content():
    config = Config.from_env(
        {
            "FIREBASE_PROJECT_ID": "qrguard-test",
            "HISTORY_STORE": "off",
            "FIREBASE_CREDENTIALS_JSON": "{nope SECRET",
        }
    )
    with pytest.raises(ValueError) as info:
        fs.init_firebase_app(config)
    assert "SECRET" not in str(info.value)


def test_delete_auth_user(monkeypatch):
    calls = []
    monkeypatch.setattr(auth, "delete_user", lambda uid, app: calls.append(uid))
    assert fs.delete_auth_user(object(), "u1") is True and calls == ["u1"]

    def missing(uid, app):
        raise auth.UserNotFoundError("gone")

    monkeypatch.setattr(auth, "delete_user", missing)
    assert fs.delete_auth_user(object(), "u1") is True

    def broken(uid, app):
        raise RuntimeError("network")

    monkeypatch.setattr(auth, "delete_user", broken)
    assert fs.delete_auth_user(object(), "u1") is False
