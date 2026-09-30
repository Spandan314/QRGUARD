"""Structured (JSON) logging with privacy safeguards.

Rules for everyone writing log statements in QRGUARD:

* NEVER log user content: message text, OCR text, full URLs, QR payloads, uploaded files.
* Log identifiers and outcomes instead: request_id, route, status, duration, risk level.
* Secrets (tokens, API keys) must never be logged; the filter below is a safety
  net, not a licence to log them.

One JSON object per line is easy to search in Render's log viewer and in any
other platform (Railway, Fly.io, Docker, journald).
"""

from __future__ import annotations

import json
import logging
import re
import sys
import traceback
from datetime import UTC, datetime

from flask import g, has_request_context

# Patterns that look like credentials. Anything matching is replaced with [REDACTED].
_SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    re.compile(r"(?i)((?:api[_-]?key|auth[_-]?key|token|password|secret)\s*[=:]\s*)[^\s&,;]+"),
]


def redact(text: str) -> str:
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


class JsonFormatter(logging.Formatter):
    """Formats each log record as a single JSON line."""

    # Extra attributes we allow callers to attach with logger.info(..., extra={...}).
    EXTRA_FIELDS = ("method", "path", "status", "duration_ms", "event", "provider")

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            # Newlines are escaped by json.dumps, which prevents log-injection of fake lines.
            "msg": redact(record.getMessage()),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            entry["request_id"] = request_id
        for name in self.EXTRA_FIELDS:
            value = getattr(record, name, None)
            if value is not None:
                entry[name] = value
        if record.exc_info:
            entry["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False)

    def formatException(self, ei) -> str:  # noqa: N802 - logging.Formatter API
        """Stack frames and exception types only, never exception messages.

        A message can echo user input (a URL, message text or QR payload passed to a library), so it
        is withheld. The frames (file, line, function, source line) are enough to find the bug.
        """
        chain: list[BaseException] = []
        exc: BaseException | None = ei[1]
        while exc is not None and exc not in chain:
            chain.append(exc)
            exc = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
        parts = []
        for error in reversed(chain):
            frames = "".join(traceback.format_tb(error.__traceback__))
            name = f"{type(error).__module__}.{type(error).__qualname__}"
            parts.append(f"Traceback (most recent call last):\n{frames}{name} (message withheld)")
        return "\nwhich caused:\n".join(parts)


class RequestIdFilter(logging.Filter):
    """Adds the current request ID (if any) to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        if has_request_context():
            record.request_id = getattr(g, "request_id", None)
        return True


def configure_logging(level: str) -> None:
    """Send JSON logs to stdout. Safe to call more than once (e.g. in tests)."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(RequestIdFilter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # Werkzeug's own access log would duplicate ours and prints full query strings.
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
