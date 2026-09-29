"""WSGI entry point.

Local development:   flask --app wsgi run --port 5000
Production:          gunicorn -c gunicorn.conf.py wsgi:app
"""

from dotenv import load_dotenv

# Load backend/.env if it exists (local development only). Real environment
# variables always win, and in production there is no .env file at all.
load_dotenv(override=False)

from app import create_app  # noqa: E402  (must run after load_dotenv)

app = create_app()
