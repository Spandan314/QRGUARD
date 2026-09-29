# Testing

All tests run offline. DNS, HTTP and threat-intelligence calls are replaced by fakes
(`backend/tests/fakes.py`), so no test contacts a real website. Test data is synthetic and
labelled DEMO / TEST DATA.

## Commands

```bash
cd backend && source .venv/bin/activate
pytest                                      # whole suite
pytest --cov=app --cov-report=term-missing  # with coverage
ruff check . && ruff format --check .       # lint + formatting (same as CI)
```

## What is covered

| Area | Files |
|---|---|
| Foundation: config, errors, security headers, CORS, rate limits, logging | `tests/unit/test_config.py`, `test_logging.py`, `tests/integration/test_errors.py`, `test_security_middleware.py`, `test_health.py` |
| URL analysis, lookalikes, SSRF-safe redirects | `tests/unit/test_url_*.py`, `test_lookalike.py`, `test_net_safety.py`, `test_redirect_resolver.py`, `tests/integration/test_api_url.py` |
| Scoring engine, config validation, indicator catalogue | `tests/unit/test_scoring_*.py`, `test_indicator_catalog.py` |
| Scam messages: preprocessing, rules, negation, no double counting, ReDoS timing | `tests/unit/test_text_preprocessor.py`, `test_message_rules.py`, `tests/integration/test_api_message.py` |
| Labelled demo messages (14 genuine, 25 scams) | `tests/integration/test_demo_messages.py` (`demo-data/messages.yaml`) |
| Screenshots: upload validation, OCR engine, API, privacy, rate limit | `tests/unit/test_image_validation.py`, `test_ocr.py`, `tests/integration/test_api_screenshot.py` |
| Threat intelligence: local feed hit/miss, URLhaus / Safe Browsing / VirusTotal / PhishTank answers, timeouts, HTTP errors, missing keys, malformed responses, several and conflicting providers, cache hit/expiry, time budget, key privacy (responses, health, logs, repr), score integration, feed download command | `tests/unit/test_threat_intel_providers.py`, `test_threat_intel_service.py`, `tests/integration/test_api_threat_intel.py` (all external APIs are faked with `FakeHttp`; no test contacts a provider) |
| QR: payload classification/parsing, OpenCV decoding (normal, inverted, several codes), generator escaping, API parity with the URL/message endpoints, Wi-Fi password masking, QR codes in screenshots | `tests/unit/test_qr_payload.py`, `test_qr_decoder.py`, `test_qr_generator.py`, `tests/integration/test_api_qr.py` |

## OCR tests

- Most screenshot tests use `FakeOcrEngine`, so they are deterministic and need no Tesseract.
- Tests marked with `real_ocr` (and `test_real_tesseract_reads_text`) run the **real** Tesseract
  on images generated at test time (`tests/images.py`). They are **skipped** when Tesseract is not
  installed. Install it to run them: `sudo apt install tesseract-ocr` (CI does this).

## Postman / Newman (API level)

The collection `postman/QRGUARD.postman_collection.json` covers health, URL, message,
screenshot and QR analysis, the QR generator and threat intelligence (demo blocklist), including
error cases (64 requests, 261 assertions). It needs no API keys. Screenshot and QR-image requests upload the synthetic images in
`postman/fixtures/` (regenerate them with `python ../postman/fixtures/generate_fixtures.py` from
`backend/`).

```bash
# terminal 1 (from backend/): relax the rate limits for this run only, because the collection
# sends 8 screenshots (default limit 6/min) and more than 20 URL/QR analyses (default 20/min)
# within a few seconds. The production defaults stay unchanged; rate limiting itself is tested
# with pytest.
RATELIMIT_SCREENSHOT="60 per minute" RATELIMIT_ANALYZE="200 per minute" flask --app wsgi run --port 5000

# terminal 2 (from the repository root)
npx newman run postman/QRGUARD.postman_collection.json --working-dir postman
```

Rate limiting itself is tested with pytest (`test_rate_limit_for_screenshots`,
`test_rate_limit_returns_429_with_retry_after`).
