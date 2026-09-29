# QRGUARD Backend (Flask REST API)

**Status: Phase 2, backend foundation.** Configuration, validation, error handling, logging, security
middleware, rate limiting and `GET /api/health` are working. The analysis endpoints validate
requests against the API contract and answer `501 NOT_IMPLEMENTED` until each module is built.

## Requirements

- Python **3.11 or 3.12** (`python --version`)
- Git
- Optional now, needed from Phase 3: **Tesseract OCR**
  (Ubuntu: `sudo apt install tesseract-ocr`; Windows: UB-Mannheim installer; macOS: `brew install tesseract`)

## 1. Set up

```bash
cd QRGUARD/backend

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # Windows PowerShell: .venv\Scripts\Activate.ps1
                                   # Windows cmd:        .venv\Scripts\activate.bat

# Install runtime + development dependencies
python -m pip install --upgrade pip
pip install -r requirements-dev.txt

# Create your local settings file (defaults are fine for development)
cp .env.example .env               # Windows: copy .env.example .env
```

## 2. Run locally

```bash
flask --app wsgi run --port 5000
```

Expected output (JSON log lines):

```
{"ts": "...", "level": "INFO", "logger": "app", "msg": "QRGUARD backend started (env=development, version=0.1.0)"}
 * Running on http://127.0.0.1:5000
```

To test from a phone on the same Wi-Fi later, run `flask --app wsgi run --host 0.0.0.0 --port 5000`.

Production-style run (Linux/macOS only, gunicorn does not run on Windows):

```bash
gunicorn -c gunicorn.conf.py wsgi:app
```

## 3. Test `/api/health`

- **Browser:** open http://localhost:5000/api/health
- **curl:** `curl -i http://localhost:5000/api/health`
- **Postman:** *Import* `postman/QRGUARD.postman_collection.json` and
  `postman/QRGUARD.local.postman_environment.json`, select the "QRGUARD local" environment,
  then run the collection. All 12 requests should pass.

Expected response (`200 OK`):

```json
{
  "status": "ok",
  "service": "qrguard-backend",
  "engine_version": "0.1.0",
  "time": "2026-09-29T08:00:00+00:00",
  "components": {
    "api": "ok",
    "scoring_config": { "status": "loaded", "version": 1, "thresholds": { "suspicious": 30, "malicious": 60 } },
    "ocr_engine": "available"
  }
}
```

`ocr_engine` shows `not_installed` if Tesseract is not installed yet. That is fine until Phase 3.

Try an endpoint that is not implemented yet:

```bash
curl -i -X POST http://localhost:5000/api/analyze/url \
     -H "Content-Type: application/json" -d '{"url": "https://example.com"}'
# → 501 {"error": {"code": "NOT_IMPLEMENTED", ...}}

curl -i -X POST http://localhost:5000/api/analyze/url \
     -H "Content-Type: application/json" -d '{}'
# → 400 {"error": {"code": "VALIDATION_ERROR", "details": [{"field": "url", ...}]}}
```

## 4. Run the tests and linter

```bash
pytest                                   # expected: 57 passed
pytest --cov=app --cov-report=term-missing
ruff check . && ruff format --check .    # expected: All checks passed!
```

## 5. Docker (same image Render will use)

```bash
docker build -t qrguard-backend .
docker run --rm -p 5000:5000 -e PORT=5000 -e ALLOWED_ORIGINS=http://localhost:5173 qrguard-backend
```

## Layout

```
backend/
├── app/
│   ├── __init__.py        create_app() factory: wires config, CORS, limiter, middleware, routes
│   ├── config.py          Config.from_env(): validated settings from environment variables
│   ├── version.py         engine version
│   ├── extensions.py      Flask-Limiter instance + rate-limit functions
│   ├── errors.py          APIError + JSON error handlers
│   ├── middleware.py      request ID, JSON size limit, security headers, access log
│   ├── logging_setup.py   JSON logs with secret redaction
│   ├── schemas.py         Pydantic request models (the API contract)
│   ├── routes/            health, analyze, generate, history blueprints
│   ├── scoring/           scoring_config.yaml (ONE place for weights/thresholds) + loader
│   └── utils/validation.py  parse_json_body(), require_multipart_file()
├── tests/{unit,integration}
├── wsgi.py  gunicorn.conf.py  Dockerfile  requirements*.txt  pyproject.toml  .env.example
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'flask'` | The virtual environment isn't active. Run `source .venv/bin/activate` again. |
| `Could not locate a Flask application` | Run the command from inside `backend/`, and use `--app wsgi`. |
| `ConfigError: ALLOWED_ORIGINS entry must start with http(s)://` | Write full origins, e.g. `http://localhost:5173`. |
| `ScoringConfigError: module_weights must add up to 1.0` | Fix `app/scoring/scoring_config.yaml`. |
| `Address already in use` | Another process uses port 5000 (on macOS, often AirPlay). Use `--port 5001` and update Postman's `baseUrl`. |
| PowerShell refuses to run `Activate.ps1` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `429 RATE_LIMITED` while testing | Wait a minute, or raise `RATELIMIT_ANALYZE` in `.env` for local development. |
| Browser shows a CORS error | Add the web app's exact origin to `ALLOWED_ORIGINS` and restart. |
