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
| Sign-in and history: token checks (missing/invalid/expired/foreign/oversized), per-uid rate limits, saving and privacy minimisation (no text, OCR, payloads, passwords, evidence or full URLs in stored records), pagination, cross-user isolation, delete one/all/my data, settings, reports, admin claim, anonymous stats, store failures, unsafe configuration refused in production | `tests/integration/test_api_history.py`, `tests/unit/test_firebase_service.py` (in-memory store and dev tokens; the Firebase SDK is faked) |
| Firestore: the real Firestore store (CRUD, pagination, batched deletes, counters, reports) and the security rules (owner-only reads/deletes, no client-written verdicts, no settings escalation, closed server collections) | `tests/integration/test_firestore_store.py` (marker `firestore_emulator`, skipped without the emulator), `firebase/tests/rules.test.js` |
| QR: payload classification/parsing, OpenCV decoding (normal, inverted, several codes), generator escaping, API parity with the URL/message endpoints, Wi-Fi password masking, QR codes in screenshots | `tests/unit/test_qr_payload.py`, `test_qr_decoder.py`, `test_qr_generator.py`, `tests/integration/test_api_qr.py` |

## OCR tests

- Most screenshot tests use `FakeOcrEngine`, so they are deterministic and need no Tesseract.
- Tests marked with `real_ocr` (and `test_real_tesseract_reads_text`) run the **real** Tesseract
  on images generated at test time (`tests/images.py`). They are **skipped** when Tesseract is not
  installed. Install it to run them: `sudo apt install tesseract-ocr` (CI does this).

## Firestore emulator (rules + Firestore store)

Needs Java 11+ and Node. No Google account or secrets: the emulator runs locally with the
`demo-qrguard` project.

```bash
cd firebase && npm ci
npm run test:rules      # security rules (firebase/tests/rules.test.js)
npm run test:backend    # backend Firestore store tests (pytest -m firestore_emulator)
```

CI runs both in the `firestore` job of `backend-ci.yml`.

## Postman / Newman (API level)

The collection `postman/QRGUARD.postman_collection.json` covers health, URL, message,
screenshot and QR analysis, the QR generator, threat intelligence (demo blocklist) and sign-in /
history / reports / admin, including error cases (83 requests, 303 assertions). It needs no API
keys and no Firebase project: history requests use dev tokens and the in-memory store. Screenshot and QR-image requests upload the synthetic images in
`postman/fixtures/` (regenerate them with `python ../postman/fixtures/generate_fixtures.py` from
`backend/`).

```bash
# terminal 1 (from backend/): relax the rate limits for this run only, because the collection
# sends 8 screenshots (default limit 6/min) and more than 20 URL/QR analyses (default 20/min)
# within a few seconds. The production defaults stay unchanged; rate limiting itself is tested
# with pytest.
# AUTH_DEV_TOKENS / HISTORY_STORE=memory enable the history requests without Firebase
# (both are refused when APP_ENV=production).
RATELIMIT_SCREENSHOT="60 per minute" RATELIMIT_ANALYZE="200 per minute" \
  AUTH_DEV_TOKENS=true HISTORY_STORE=memory flask --app wsgi run --port 5000

# terminal 2 (from the repository root)
npx newman run postman/QRGUARD.postman_collection.json --working-dir postman
```

Rate limiting itself is tested with pytest (`test_rate_limit_for_screenshots`,
`test_rate_limit_returns_429_with_retry_after`).

## End-to-end (whole system, no mocks)

`e2e/run.sh` builds the web app and the mobile app (Expo web export) in Firebase mode, starts the
Firebase Auth + Firestore emulators, the Flask backend under Gunicorn and static servers, then drives
Chromium through both apps (`e2e/tests/web.mjs`, `e2e/tests/mobile.mjs`):

```bash
# once: backend/.venv with requirements-dev.txt, `npm ci` in web/, mobile/, firebase/, e2e/, Java 21
bash e2e/run.sh            # web + mobile
bash e2e/run.sh web        # web only
CHROMIUM_PATH=/path/to/chrome bash e2e/run.sh   # use a local Chrome/Chromium
```

| Flow | Checked |
|---|---|
| Anonymous Firebase sign-in → profile from Flask | web + mobile |
| Link check → threat-intelligence hit → MALICIOUS / *Verified by threat intelligence* → saved to Firestore | web + mobile |
| Report a result (linked to the saved scan) | web |
| Message check saved; history never shows the text or full URL | web + mobile |
| **Live camera** QR scan (Chromium fake camera plays a generated UPI-refund QR video) → SUSPICIOUS | web |
| Second user sees an empty history (isolation) | web + mobile |
| Non-admin refused (page and API); admin claim granted with `flask set-admin`, stats + report review | web |
| Delete my data → history gone, signed out (with the confirmation dialog) | web + mobile |
| 375 px width: no horizontal scroll | web |
| Backend log contains no ID tokens, URLs, message text or QR payloads | log scan |

Screenshots and the backend log are written to `e2e/artifacts/`. CI: `.github/workflows/e2e.yml`.
The native camera and gallery on a real phone cannot be automated here; check them on a device
(scan a printed QR code, pick a screenshot, deny and re-allow camera permission).

## Evaluation

`python -m scripts.evaluate` (in `backend/`) measures precision/recall on a held-out labelled set
and the tuning set; results and error analysis are in [evaluation.md](evaluation.md).
