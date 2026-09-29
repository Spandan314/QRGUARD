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
| QR: payload classification/parsing, OpenCV decoding (normal, inverted, several codes), generator escaping, API parity with the URL/message endpoints, Wi-Fi password masking, QR codes in screenshots | `tests/unit/test_qr_payload.py`, `test_qr_decoder.py`, `test_qr_generator.py`, `tests/integration/test_api_qr.py` |

## OCR tests

- Most screenshot tests use `FakeOcrEngine`, so they are deterministic and need no Tesseract.
- Tests marked with `real_ocr` (and `test_real_tesseract_reads_text`) run the **real** Tesseract
  on images generated at test time (`tests/images.py`). They are **skipped** when Tesseract is not
  installed. Install it to run them: `sudo apt install tesseract-ocr` (CI does this).

## Postman / Newman (API level)

The collection `postman/QRGUARD.postman_collection.json` covers health, URL, message,
screenshot and QR analysis and the QR generator, including error cases (58 requests, 232
assertions). Screenshot and QR-image requests upload the synthetic images in
`postman/fixtures/` (regenerate them with `python ../postman/fixtures/generate_fixtures.py` from
`backend/`).

```bash
# terminal 1 (from backend/): relax only the OCR rate limit, because the collection sends
# 8 screenshots in a few seconds and the default limit is 6 per minute. Start a fresh server for
# each run: the collection sends 15 QR requests and the analysis limit is 20 per minute
RATELIMIT_SCREENSHOT="60 per minute" flask --app wsgi run --port 5000

# terminal 2 (from the repository root)
npx newman run postman/QRGUARD.postman_collection.json --working-dir postman
```

Rate limiting itself is tested with pytest (`test_rate_limit_for_screenshots`,
`test_rate_limit_returns_429_with_retry_after`).
