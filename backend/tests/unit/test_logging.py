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


def _record_for(exc: BaseException) -> logging.LogRecord:
    try:
        raise exc
    except BaseException:
        import sys

        return logging.LogRecord("t", logging.ERROR, __file__, 1, "boom", None, sys.exc_info())


def test_exception_messages_are_never_logged_only_types_and_frames():
    # A library error message can echo user input (a URL, message text, a QR payload). The input
    # arrives in variables, so it only reaches the log through the exception message.
    url = "https://victim.example/reset?code=" + "USERDATA" + "1"
    text = "Dear customer " + "USERDATA" + "2"
    try:
        try:
            raise ValueError(f"inner {url}")
        except ValueError as inner:
            raise RuntimeError(f"outer: {text}") from inner
    except RuntimeError as outer:
        record = _record_for(outer)
    data = json.loads(JsonFormatter().format(record))
    assert "USERDATA1" not in data["exc"] and "USERDATA2" not in data["exc"]
    assert "victim.example" not in data["exc"]
    # Still useful for debugging: exception types and where they were raised.
    assert "builtins.ValueError" in data["exc"] and "builtins.RuntimeError" in data["exc"]
    assert "test_logging.py" in data["exc"]
