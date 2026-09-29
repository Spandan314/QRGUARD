"""Gunicorn settings for production.

Everything is read from environment variables, so the same file works on
Render, Railway, Fly.io, Docker or a plain VM.
"""

import os

# Render (and most platforms) tell the app which port to listen on via $PORT.
bind = f"0.0.0.0:{os.environ.get('PORT', '5000')}"

# 2 workers x 4 threads fits comfortably in a 512 MB free-tier instance.
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
threads = int(os.environ.get("GUNICORN_THREADS", "4"))

# OCR requests can take several seconds; 60 s is a generous upper bound.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))
graceful_timeout = 30

# Our Flask middleware already writes a JSON access log (without query strings),
# so gunicorn's own access log is disabled. Errors still go to stderr.
accesslog = None
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info").lower()
