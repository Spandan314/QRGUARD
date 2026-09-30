"""The post-deployment smoke test, run against a real HTTP server on localhost."""

import threading

import pytest
from werkzeug.serving import make_server

from app import create_app
from app.config import Config
from scripts import smoke_test

WEB = "https://web.qrguard.test"


@pytest.fixture(scope="module")
def base_url():
    app = create_app(
        Config.from_env(
            {
                "APP_ENV": "testing",
                "ALLOWED_ORIGINS": WEB,
                "REDIRECT_RESOLUTION": "off",
                "RATELIMIT_ANALYZE": "1000 per minute",
                "RATELIMIT_DEFAULT": "1000 per minute",
            }
        )
    )
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_passes_against_a_correctly_configured_backend(base_url, capsys):
    assert smoke_test.main([base_url, "--web-origin", WEB]) == 0
    assert "11/11 checks passed" in capsys.readouterr().out


def test_reports_a_cors_misconfiguration(base_url, capsys):
    assert smoke_test.main([base_url, "--web-origin", "https://other.qrguard.test"]) == 1
    assert "FAIL  CORS allows https://other.qrguard.test" in capsys.readouterr().out


def test_expect_raises_even_when_asserts_are_disabled():
    with pytest.raises(smoke_test.CheckFailed):
        smoke_test.expect(False, "boom")
