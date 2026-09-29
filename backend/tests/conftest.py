"""Shared pytest fixtures.

Tests build their configuration from an explicit dict (not the real environment
or a .env file), so they give the same result on every machine and in CI.
"""

import pytest

from app import create_app
from app.config import Config
from app.extensions import limiter

BASE_TEST_ENV = {
    "APP_ENV": "testing",
    "LOG_LEVEL": "WARNING",
    "ALLOWED_ORIGINS": "http://localhost:5173",
    "RATELIMIT_DEFAULT": "1000 per minute",
    "RATELIMIT_ANALYZE": "1000 per minute",
}


def make_app(**overrides: str):
    env = {**BASE_TEST_ENV, **overrides}
    app = create_app(Config.from_env(env))
    limiter.reset()  # the limiter is shared between apps; start every test with clean counters
    return app


@pytest.fixture
def app():
    return make_app()


@pytest.fixture
def client(app):
    return app.test_client()
