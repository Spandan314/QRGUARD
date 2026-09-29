# QRGUARD Backend (Flask REST API)

**Status:** the backend foundation and **URL analysis + risk scoring** are working
(`POST /api/analyze/url`). The message, screenshot and QR endpoints validate requests against the
API contract and answer `501 NOT_IMPLEMENTED` until their modules are built. No threat-intelligence
provider is connected yet; responses say so explicitly.

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
  then run the collection. All 24 requests (76 checks) should pass.

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

Analyse a URL:

```bash
curl -s -X POST http://localhost:5000/api/analyze/url \
     -H "Content-Type: application/json" \
     -d '{"url": "http://sbi.co.in.kyc-verify.xyz/login"}'
# → 200 {"risk_score": 73, "risk_level": "MALICIOUS", "confidence": "HIGH", "indicators": [...], ...}

curl -s -X POST http://localhost:5000/api/analyze/url \
     -H "Content-Type: application/json" -d '{"url": "ftp://files.example.com/"}'
# → 400 {"error": {"code": "UNSUPPORTED_PROTOCOL", ...}}
```

Only link shorteners (bit.ly, tinyurl.com…) are contacted, to see where they redirect, and only through
the SSRF-protected checker (see `docs/security.md`). Set `REDIRECT_RESOLUTION=off` in `.env` to
never contact any link.

Tuning: weights, caps, floors and thresholds are in `app/scoring/scoring_config.yaml`. Shorteners,
TLDs, keywords and trusted domains are in `app/data/url_rules.yaml`, and brands in
`app/data/brands.yaml`. Restart the server after editing; invalid files stop startup with a clear
error.

## 4. Run the tests and linter

```bash
pytest                                   # expected: 263 passed (no internet needed)
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
│   ├── analyzers/         url_normalizer, url_features, lookalike, redirect_resolver, url_rules
│   ├── services/          url_analysis_service (pipeline: normalise → features → redirects → TI → score)
│   ├── scoring/           scoring_config.yaml (ONE place for weights/floors/thresholds),
│   │                      settings (validation), engine, indicator, recommendations
│   ├── threat_intelligence/  provider interface + service (providers come later)
│   ├── data/              url_rules.yaml, brands.yaml (editable rule lists)
│   └── utils/             validation.py, net_safety.py (SSRF checks, DNS with timeout)
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
| `ScoringConfigError: indicator X: unknown category` | Every indicator's `category` must be listed in `category_caps`. |
| `UrlRulesError` at startup | A YAML list in `app/data/` is malformed; the message names the field. |
| Shortened links show `redirects.status: "timeout"` | The server could not reach the shortener within 3 s (offline laptop, firewall). The result is still returned, with LOW confidence. |
| A legitimate site is flagged as a lookalike | Add its domain to the brand's `official_domains` in `app/data/brands.yaml`. |
