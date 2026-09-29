import json
import logging

from app.logging_setup import JsonFormatter, redact


def test_redacts_bearer_tokens_and_keys():
    assert "abc.def" not in redact("Authorization: Bearer abc.def")
    assert "SECRET123" not in redact("calling api?api_key=SECRET123&x=1")
    assert "hunter2" not in redact("password: hunter2")


def test_json_formatter_outputs_one_line_json():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "line1\nline2", None, None)
    record.status = 200
    line = JsonFormatter().format(record)
    assert "\n" not in line  # newlines escaped -> no log injection
    data = json.loads(line)
    assert data["msg"] == "line1\nline2"
    assert data["status"] == 200
    assert data["level"] == "INFO"
