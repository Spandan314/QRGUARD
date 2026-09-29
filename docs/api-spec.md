# REST API Specification (v1 contract)

- **Base URL:** `https://<render-service>.onrender.com` (local: `http://localhost:5000`)
- **Format:** JSON (UTF-8), except uploads, which use `multipart/form-data`.
- **Auth:** `Authorization: Bearer <Firebase ID token>`. This is **optional** for analysis (anonymous
  callers get stricter rate limits and no history) and **required** for history, reports and admin
  (see "Sign-in, history, reports, admin" below).
- **Versioning:** the paths below are frozen for v1. Breaking changes need a new prefix (`/api/v2`).
  Every response carries `engine_version`.

## 1. Common result object (`AnalysisResult`)

Returned by all four `/api/analyze/*` endpoints. Implemented for `/api/analyze/url` (v0.1.0).
The example below is a real response for `http://sbi.co.in.kyc-verify.xyz/login` (shortened).

```json
{
  "request_id": "7917ce154f334c1d",
  "input_type": "url",
  "risk_score": 73,
  "risk_level": "MALICIOUS",
  "confidence": "HIGH",
  "verification": {
    "status": "UNVERIFIED",
    "source": null,
    "message": "There is insufficient evidence to establish trust. A SAFE result does not guarantee that the website is safe."
  },
  "summary": "Strong warning signs: this link is very likely malicious.",
  "categories": [
    { "id": "phishing", "label": "Phishing" },
    { "id": "impersonation", "label": "Impersonation scam" }
  ],
  "indicators": [
    {
      "id": "OFFICIAL_DOMAIN_IN_SUBDOMAIN",
      "severity": "critical",
      "title": "Real brand address used as a disguise",
      "message": "A genuine brand's web address appears at the start of this link, but the link actually belongs to a different domain.",
      "evidence": "State Bank of India",
      "weight": 40,
      "score_contribution": 40.0,
      "module": "url_qr"
    },
    { "id": "URL_SUSPICIOUS_TLD", "severity": "medium", "evidence": ".xyz", "weight": 10, "score_contribution": 10.0, "…": "…" },
    { "id": "URL_NO_HTTPS", "severity": "low", "evidence": "http://", "weight": 8, "score_contribution": 8.0, "…": "…" }
  ],
  "recommendation": "Do not open this link and do not enter any personal, banking, OTP, PIN or payment details. … In India, report financial fraud at 1930 or https://cybercrime.gov.in.",
  "score_breakdown": {
    "modules": [
      { "module": "url_qr", "applicable": true, "module_score": 73.0, "weight": 0.35, "effective_weight": 1.0 },
      { "module": "threat_intel", "applicable": false, "module_score": null, "weight": 0.3, "effective_weight": 0.0 },
      { "module": "message", "applicable": false, "module_score": null, "weight": 0.2, "effective_weight": 0.0 },
      { "module": "ocr", "applicable": false, "module_score": null, "weight": 0.15, "effective_weight": 0.0 }
    ],
    "weighted_score": 73.0,
    "floor_applied": null,
    "final_score": 73
  },
  "threat_intel": {
    "checked": true,
    "providers": [
      { "provider": "local_feed", "status": "not_listed", "limited_coverage": true },
      { "provider": "urlhaus", "status": "disabled" },
      { "provider": "google_safe_browsing", "status": "disabled" },
      { "provider": "virustotal", "status": "disabled" },
      { "provider": "phishtank", "status": "disabled" }
    ],
    "note": "Only QRGUARD's small demo blocklist could be checked. Not being listed does not mean a link is safe."
  },
  "analysis": { "…": "endpoint-specific, see below" },
  "disclaimer": "This is an automated security assessment, not a guarantee.",
  "engine_version": "0.1.0"
}
```

| Field | Meaning |
|---|---|
| `risk_level` | `SAFE` · `SUSPICIOUS` · `MALICIOUS`, from the score only (see below) |
| `verification.status` | `VERIFIED` · `UNVERIFIED`. Never changes the score or level. |
| `verification.source` | `trusted_domain_list` · `threat_intelligence` · `null` |
| `verification.message` | Plain-language explanation of the verification status |
| `confidence` | `LOW` · `MEDIUM` · `HIGH`: how much evidence the verdict rests on |
| `categories` | Scam categories (multi-label). Only for SUSPICIOUS/MALICIOUS. **They never add points.** |
| `indicators[].severity` | `info` · `low` · `medium` · `high` · `critical` (derived from weight; any floor = critical) |
| `indicators[].weight` | Nominal points from `scoring_config.yaml` (negative = sign of legitimacy) |
| `indicators[].score_contribution` | Points this indicator actually added to the final score, after caps and module weighting |
| `indicators[].evidence` | Short, user-safe detail. It never contains resolved IPs or raw provider data. |
| `score_breakdown.floor_applied` | `{indicator, minimum_score, points_added}` when a critical finding raised the score |
| `threat_intel.providers[].status` | `listed` · `partial` · `not_listed` · `unavailable` · `disabled` · `error` |
| `threat_intel.providers[]` (optional fields) | `threat_type` (listed/partial only), `detail` (e.g. `timeout`, `rate limited`, `configuration`, `5/94 engines`), `limited_coverage: true` (demo blocklist only), `cached: true` |
| `threat_intel.checked` / `note` | `checked` is true when at least one source is enabled. `not_listed` never lowers a score; see docs/threat-intelligence.md |

### Risk levels and verification

| Level | Score | Meaning |
|---|---|---|
| **SAFE** | 0–29 | No significant suspicious indicators detected. **Not a guarantee of safety.** |
| **SUSPICIOUS** | 30–59 | Several warning signs; the link should not be trusted. |
| **MALICIOUS** | 60–100 | Strong or decisive evidence of harm. |

| `verification` | Meaning |
|---|---|
| `{"status": "VERIFIED", "source": "trusted_domain_list"}` | Domain on the curated trusted list and no medium-or-worse finding |
| `{"status": "VERIFIED", "source": "threat_intelligence"}` | A threat-intelligence provider lists the input as malicious |
| `{"status": "UNVERIFIED", "source": null}` | Insufficient evidence to establish trust. **SAFE + UNVERIFIED is valid** and must be shown to users as "not guaranteed safe". |

"Not found in a threat database" never produces VERIFIED.

Examples (real output):

```json
{ "risk_score": 0, "risk_level": "SAFE", "confidence": "MEDIUM",
  "verification": { "status": "VERIFIED", "source": "trusted_domain_list",
                    "message": "The domain is on QRGUARD's list of recognised legitimate websites." } }

{ "risk_score": 0, "risk_level": "SAFE", "confidence": "LOW",
  "verification": { "status": "UNVERIFIED", "source": null,
                    "message": "There is insufficient evidence to establish trust. A SAFE result does not guarantee that the website is safe." } }

{ "risk_score": 90, "risk_level": "MALICIOUS", "confidence": "HIGH",
  "verification": { "status": "VERIFIED", "source": "threat_intelligence",
                    "message": "A threat-intelligence source lists this as known malicious." } }
```

## 2. Common error object

```json
{ "error": { "code": "FILE_TOO_LARGE", "message": "Image must be 5 MB or smaller.", "request_id": "b7c1e0f2a9" } }
```

| HTTP | `code` examples | When |
|---|---|---|
| 400 | `INVALID_JSON`, `VALIDATION_ERROR`, `EMPTY_URL`, `INVALID_URL`, `UNSUPPORTED_PROTOCOL`, `MISSING_FILE`, `NO_QR_FOUND` | Bad input |
| 401 | `AUTH_REQUIRED`, `INVALID_TOKEN` | Missing or expired token on protected routes |
| 403 | `FORBIDDEN` | Not an admin, or not the owner |
| 404 | `NOT_FOUND` | Unknown route or scan ID |
| 405 | `METHOD_NOT_ALLOWED` | |
| 413 | `FILE_TOO_LARGE`, `PAYLOAD_TOO_LARGE` | Above `MAX_UPLOAD_MB` or the JSON limit |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Not PNG/JPEG/WEBP, or wrong Content-Type |
| 422 | `TEXT_NOT_ANALYZABLE`, `UNPROCESSABLE_IMAGE`, `OCR_FAILED` | No analysable text; corrupt image; OCR produced nothing |
| 429 | `RATE_LIMITED` | Includes a `Retry-After` header |
| 501 | `NOT_IMPLEMENTED` | Endpoint validated the request, but its analyzer is not built yet |
| 500 | `INTERNAL_ERROR` | Generic message only. The stack trace goes to server logs, never to the client. |
| 503 | `SERVICE_UNAVAILABLE` | e.g. history requested but Firebase is not configured |

## 3. Endpoints

### `GET /api/health`
Public and exempt from rate limiting.
```json
{ "status": "ok", "service": "qrguard-backend", "engine_version": "0.1.0", "time": "2026-09-29T10:00:00+00:00",
  "components": { "api": "ok",
                  "scoring_config": { "status": "loaded", "version": 2, "thresholds": { "suspicious": 30, "malicious": 60 } },
                  "ocr_engine": "available",
                  "threat_intel": { "enabled": true,
                                    "providers": [ { "provider": "local_feed", "enabled": true, "external": false },
                                                   { "provider": "urlhaus", "enabled": false, "external": true },
                                                   { "provider": "google_safe_browsing", "enabled": false, "external": true },
                                                   { "provider": "virustotal", "enabled": false, "external": true },
                                                   { "provider": "phishtank", "enabled": false, "external": true } ] } } }
```
`threat_intel` shows only which sources are on (an API key is set) and whether they send URLs to a
third party (`external`). It never contains keys, feed paths or quotas.

### `POST /api/analyze/url` ✅ implemented

Request:
```json
{ "url": "https://bit.ly/demo", "save_to_history": false }
```

Input rules:
- `url` is a string of 1–2048 characters after trimming. Unknown fields are rejected.
- A missing scheme (`example.com`) is analysed as `https://` and reported with the info indicator
  `URL_SCHEME_ASSUMED`.
- `http` and `https` are analysed. `javascript:`, `data:`, `vbscript:`, `file:`, `blob:` and
  `intent:` are **analysed as MALICIOUS** (floor 80); they are not errors.
- Other schemes (`ftp:`, `mailto:`, `tel:`, `upi:` …) → `400 UNSUPPORTED_PROTOCOL`.
- Malformed input (no host, spaces, invalid characters or port) → `400 INVALID_URL`. Whitespace-only
  input → `400 VALIDATION_ERROR`.
- `save_to_history: true` saves the verdict for a signed-in user (see "Sign-in, history, reports, admin").

`analysis` for `https://bit.ly/demo` (generated by the code, with the redirect to `https://www.example.com/offer` simulated by the test fakes):
```json
{
  "input_url": "https://bit.ly/demo",
  "normalized_url": "https://bit.ly/demo",
  "scheme": "https",
  "host": "bit.ly",
  "host_unicode": null,
  "domain": "bit.ly",
  "subdomain": null,
  "public_suffix": "ly",
  "port": null,
  "brand": null,
  "features": {
    "url_length": 19, "host_length": 6, "path_length": 5, "query_length": 0,
    "subdomain_count": 0, "hyphens_in_domain": 0, "digits_in_host": 0,
    "special_char_count": 0, "special_char_ratio": 0.0, "encoded_char_count": 0,
    "uses_https": true, "is_ip_address": false, "is_private_or_local": false,
    "has_userinfo": false, "has_nonstandard_port": false, "is_punycode": false,
    "is_shortener": true, "is_user_content_host": false, "suspicious_tld": false,
    "executable_download": false, "phishing_keywords": [], "is_trusted_domain": false
  },
  "redirects": {
    "checked": true,
    "status": "completed",
    "redirect_count": 1,
    "hops": [ { "url": "https://bit.ly/demo", "status_code": 301 },
              { "url": "https://www.example.com/offer", "status_code": 200 } ],
    "final_url": "https://www.example.com/offer",
    "final_domain": "example.com"
  }
}
```

- `host_unicode` is only set for international (IDN) domains, e.g. `"pаypal.com"` for `xn--pypal-4ve.com`.
- `brand` is `{"brand": "HDFC Bank", "match_type": "official" | "lookalike" | "impersonation"}` or `null`.
- `redirects.status` ∈ `completed`, `not_attempted` (with `reason`), `too_many_redirects`,
  `blocked_private_address`, `blocked_dangerous_scheme`, `blocked_scheme`, `blocked_port`,
  `dns_failure`, `timeout`, `connection_error`, `tls_error`, `invalid_redirect`.

### `POST /api/analyze/message` ✅ implemented

Request:
```json
{ "text": "Dear customer, your SBI account will be BLOCKED today. Update your KYC immediately: http://sbi-kyc-update.xyz/login",
  "save_to_history": false }
```

| Status | When |
|---|---|
| 200 | Analysis result (common result object) |
| 400 `VALIDATION_ERROR` | Missing / empty / whitespace-only / > 5000 characters / not a string / unknown field |
| 422 `TEXT_NOT_ANALYZABLE` | Fewer than 3 letters and no link (e.g. only emojis or numbers) |
| 413 / 415 / 429 | As for all endpoints |

Real response (shortened; the redirect check was not needed because the link is not a shortener):

```json
{
  "input_type": "message",
  "risk_score": 65,
  "risk_level": "MALICIOUS",
  "confidence": "HIGH",
  "verification": { "status": "UNVERIFIED", "source": null,
                    "message": "There is insufficient evidence to establish trust. A SAFE result does not guarantee that the message is genuine." },
  "summary": "Strong warning signs: this message is very likely a scam.",
  "categories": [ { "id": "kyc_account_suspension", "label": "KYC / account suspension scam" },
                  { "id": "phishing", "label": "Phishing" },
                  { "id": "banking_payment", "label": "Banking / payment scam" } ],
  "indicators": [
    { "id": "MSG_KYC_PRETEXT", "source": "message", "severity": "medium", "evidence": "update your kyc", "weight": 15, "score_contribution": 15.0 },
    { "id": "MSG_COMBO_THREAT_URGENCY_ACTION", "source": "combination", "severity": "medium", "evidence": "account threat + urgency + link", "weight": 15, "score_contribution": 15.0 },
    { "id": "MSG_ACCOUNT_THREAT", "source": "message", "severity": "medium", "evidence": "account will be blocked", "weight": 15, "score_contribution": 12.0 },
    { "id": "MSG_LINK_CALL_TO_ACTION", "source": "message", "severity": "medium", "evidence": "update … [link]", "weight": 10, "score_contribution": 10.0 },
    { "id": "MSG_URGENCY", "source": "message", "severity": "medium", "evidence": "immediately", "weight": 10, "score_contribution": 8.0 },
    { "id": "MSG_BANK_REFERENCE", "source": "message", "severity": "low", "evidence": "sbi", "weight": 5, "score_contribution": 5.0 },
    { "id": "BRAND_IN_DOMAIN_NAME", "source": "link", "severity": "high", "evidence": "sbi-kyc-update.xyz: State Bank of India", "weight": 25, "score_contribution": 0.0 },
    { "id": "URL_SUSPICIOUS_TLD", "source": "link", "severity": "medium", "evidence": "sbi-kyc-update.xyz: .xyz", "weight": 10, "score_contribution": 0.0 }
  ],
  "recommendation": "Do not reply, call back, click links, pay, or share any OTP, PIN, password or card details. Block and report the sender. … In India, report financial fraud at 1930 or https://cybercrime.gov.in. Suspected fraud calls and messages can be reported through Chakshu on https://sancharsaathi.gov.in.",
  "score_breakdown": {
    "modules": [ { "module": "url_qr", "applicable": true, "module_score": 58.0, "weight": 0.35, "effective_weight": 0.0 },
                 { "module": "message", "applicable": true, "module_score": 65.0, "weight": 0.2, "effective_weight": 1.0 }, "…" ],
    "primary_score": 65.0,
    "weighted_score": 60.5,
    "rule_used": "primary_evidence",
    "floor_applied": null,
    "final_score": 65,
    "sources": [ { "source": "message", "points": 50.0, "indicator_ids": ["MSG_KYC_PRETEXT", "MSG_ACCOUNT_THREAT", "MSG_LINK_CALL_TO_ACTION", "MSG_URGENCY", "MSG_BANK_REFERENCE"] },
                 { "source": "link", "points": 0.0, "indicator_ids": ["BRAND_IN_DOMAIN_NAME", "URL_SUSPICIOUS_TLD", "…"] },
                 { "source": "combination", "points": 15.0, "indicator_ids": ["MSG_COMBO_THREAT_URGENCY_ACTION"] } ]
  },
  "threat_intel": { "checked": true, "providers": [ { "provider": "local_feed", "status": "not_listed", "limited_coverage": true }, { "provider": "urlhaus", "status": "disabled" }, "…" ], "note": "Only QRGUARD's small demo blocklist could be checked. Not being listed does not mean a link is safe." },
  "analysis": {
    "text_length": 115,
    "language": { "script": "latin", "supported": true },
    "preprocessing": { "hidden_characters_removed": 0, "links_found": 1, "links_deobfuscated": 0 },
    "low_confidence_reasons": [],
    "matched_phrases": [ { "indicator": "MSG_ACCOUNT_THREAT", "phrase": "account will be blocked", "sentence": 1 },
                         { "indicator": "MSG_URGENCY", "phrase": "immediately", "sentence": 2 }, "…" ],
    "links": [ { "url": "http://sbi-kyc-update.xyz/login", "scored": true, "normalized_url": "http://sbi-kyc-update.xyz/login",
                 "domain": "sbi-kyc-update.xyz", "risk_score": 58, "risk_level": "SUSPICIOUS",
                 "indicator_ids": ["BRAND_IN_DOMAIN_NAME", "URL_SUSPICIOUS_TLD", "URL_NO_HTTPS", "URL_PHISHING_KEYWORD"],
                 "redirects": { "checked": false, "status": "not_attempted", "reason": "only shortened links are followed" } } ],
    "entities": { "emails": [], "upi_ids": [], "amounts": [], "phone_numbers": [] }
  },
  "disclaimer": "This is an automated security assessment, not a guarantee.",
  "engine_version": "0.1.0"
}
```

Notes:
- `indicators[].source` ∈ `message` · `link` · `threat_intelligence` · `combination`.
  `score_breakdown.sources` gives the points per source.
- `rule_used`: `primary_evidence` (the text alone gave the highest score) or
  `weighted_with_additional_evidence` (the link raised it). A floor, if any, is in `floor_applied`.
- `links[].scored` marks the one link whose findings were scored. At most 3 links are analysed
  and at most 2 redirect checks are made per message. Extra links show `"error": "not analysed
  (limit reached)"`.
- `entities.phone_numbers` are masked (`******3210`). The text itself is never echoed except as
  short matched phrases, and never logged or stored.

### `POST /api/analyze/screenshot` ✅ implemented

`multipart/form-data` fields:

| Field | Required | Rules |
|---|---|---|
| `file` | yes | Exactly one image. PNG, JPEG or WEBP, detected from the **content** (the filename/extension is ignored). ≤ `MAX_UPLOAD_MB` (5 MB). 16×16 to 10000×10000 px and ≤ `MAX_IMAGE_MEGAPIXELS` (25 MP). |
| `save_to_history` | no | `"true"` or `"false"`; `"true"` saves the verdict for a signed-in user |

Processing: the image is validated and decoded in memory → OCR (Tesseract) → the extracted text goes
through **the same pipeline as `/api/analyze/message`**: scam-message rules, links sent to the URL
analyzer (with SSRF protection), and scoring. The screenshot therefore gets the same score,
indicators and categories as the same text pasted as a message. OCR only adds informational
indicators (`source: "ocr"`, weight 0) and can lower the confidence.

| Status | `code` | When |
|---|---|---|
| 200 | | Analysis result (common result object, `input_type: "screenshot"`) |
| 400 | `MISSING_FILE`, `EMPTY_FILE`, `VALIDATION_ERROR` | No `file` field, empty file, more than one file, invalid `save_to_history` |
| 413 | `PAYLOAD_TOO_LARGE`, `FILE_TOO_LARGE`, `IMAGE_TOO_LARGE` | Upload over 5 MB; too many pixels or a decompression-bomb header |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Not multipart, or the content is not PNG/JPEG/WEBP (GIF, PDF, SVG, executables…) |
| 422 | `UNPROCESSABLE_IMAGE`, `IMAGE_TOO_SMALL` | Corrupt/truncated image; smaller than 16×16 |
| 422 | `NO_TEXT_FOUND` | OCR found no readable text (e.g. a blank image, only emojis) |
| 422 | `OCR_FAILED` | OCR could not finish (timeout, engine error) |
| 429 | `RATE_LIMITED` | Analysis limit or the extra OCR limit `RATELIMIT_SCREENSHOT` (default 6/min, 60/day) |
| 503 | `OCR_UNAVAILABLE`, `OCR_BUSY` | Tesseract not installed / too many OCR jobs running |

`analysis` = the message `analysis` block (`matched_phrases`, `links`, `entities`, `language`,
`preprocessing`, `low_confidence_reasons`, `text_length`) **plus**:

Real output for `postman/fixtures/scam-kyc.png` (the result is 65 MALICIOUS, identical to the same
text sent to `/api/analyze/message`):

```json
{
  "ocr": {
    "engine": "tesseract",
    "extracted_text": "Demo / test data Dear customer, your SBI account will be BLOCKED today. Update your KYC immediately: http://sbi-kyc-update.xyz/login",
    "confidence": 93.8,
    "quality": "good",
    "word_count": 18,
    "truncated": false
  },
  "image": { "format": "PNG", "width": 1100, "height": 210, "size_bytes": 22347 }
}
```

- `ocr.quality`: `good` (≥ 80), `fair` (≥ 60), `poor` (< 60, adds `OCR_LOW_CONFIDENCE` and LOW
  confidence), `none`.
- `extracted_text` is returned **to the caller only**, so the user can see what was read. It is never
  logged or stored. At most 5000 characters are analysed (`OCR_TEXT_TRUNCATED` otherwise).
- QR codes inside screenshots are decoded as well (see `/api/analyze/qr` below).

### `POST /api/analyze/qr` ✅ implemented
Two accepted forms:

1. JSON (camera scan, already decoded on the device):
   `{ "content": "upi://pay?pa=abc@okaxis&pn=Shop", "source": "camera", "save_to_history": false }`
   (`content` 1–4096 chars; `source` ∈ `camera | image`).
2. `multipart/form-data`: `file` = an image containing one or more QR codes (same validation and
   limits as `/api/analyze/screenshot`: PNG/JPEG/WEBP detected from content, ≤ 5 MB, ≤ 25 MP).
   Decoded in memory with OpenCV; light-on-dark (inverted) codes are retried automatically.

What happens to the decoded content (nothing is ever opened, dialled, paid or connected to):

| `content_type` | Example | Analysed by |
|---|---|---|
| `url` | `https://…`, `www.…` | **the URL analyzer** (same result as `/api/analyze/url`, incl. SSRF-safe redirect checks and TI) |
| `dangerous` | `javascript:`, `data:`, `intent:` … | the URL analyzer (`URL_DANGEROUS_SCHEME`, floor 80) |
| `upi` | `upi://pay?pa=…&pn=…&am=…` | UPI checks: `QR_UPI_MALFORMED`, `QR_UPI_PREFILLED_AMOUNT`, `QR_UPI_NAME_MISMATCH`, `QR_UPI_PRETEXT` |
| `wifi` | `WIFI:T:WPA;S:…;P:…;;` | `QR_WIFI_OPEN`, `QR_WIFI_WEAK_SECURITY` (WEP). The password is **never** returned |
| `text`, `vcard`, `sms` body, `email` body | free text | **the scam-message rules** (same as `/api/analyze/message`) |
| `phone`, `email`, `geo`, `app_link` | `tel:`, `mailto:`, `geo:`, `market:`… | informational indicators (`QR_APP_LINK` +10) |

QR payload indicators have `source: "qr"` (URL findings keep `source: "link"`). Several codes in one
image: each is analysed and **the riskiest one decides**; all are listed in `analysis.qr_codes`.

| Status | `code` | When |
|---|---|---|
| 200 | | Analysis result (common result object, `input_type: "qr"`) |
| 400 | `VALIDATION_ERROR`, `MISSING_FILE`, `EMPTY_FILE` | Empty/too long content, unknown `source`, no file |
| 413 / 415 / 422 | as for screenshots | Upload too large / not an image / corrupt image |
| 422 | `NO_QR_FOUND` | No QR code could be read from the image |
| 429 | `RATE_LIMITED` | Analysis rate limit |

Real output for `upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund`
(40 SUSPICIOUS: a payment request dressed up as a bank refund; on its own a QR code cannot prove
fraud, so it is not MALICIOUS; see risk-scoring §13):

```json
{
  "input_type": "qr", "risk_score": 40, "risk_level": "SUSPICIOUS",
  "verification": { "status": "UNVERIFIED", "source": null,
    "message": "There is insufficient evidence to establish trust. A SAFE result does not guarantee that the QR code is safe." },
  "categories": [ { "id": "upi_scam", "label": "UPI scam" }, { "id": "impersonation", "label": "Impersonation scam" } ],
  "indicators": [ "QR_UPI_NAME_MISMATCH (+15)", "QR_UPI_PRETEXT (+15)", "QR_UPI_PREFILLED_AMOUNT (+10)", "QR_UPI_PAYMENT (0)" ],
  "analysis": {
    "qr": {
      "source": "camera", "codes_found": 1, "content_type": "upi",
      "decoded_content": "upi://pay?pa=refund.desk9912@okdemo&pn=SBI%20Refund%20Desk&am=4999&tn=Refund",
      "parsed": { "action": "pay", "payee_vpa": "refund.desk9912@okdemo", "payee_name": "SBI Refund Desk",
                  "amount": "4999", "currency": "INR", "note": "Refund", "merchant_code": null,
                  "valid_vpa": true, "valid_amount": true }
    }
  }
}
```
(`indicators` abbreviated; each is a full indicator object with `source: "qr"`.)

- For Wi-Fi codes `decoded_content` shows `P:***` and `parsed` has only `ssid`, `security`,
  `hidden`, `has_password`.
- Image uploads add `analysis.image` (format, size) and, with several codes, `analysis.qr_codes`
  (`index`, `content_type`, `decoded_content`, `risk_score`, `risk_level`, `scored`).

**QR codes inside screenshots** (`/api/analyze/screenshot`) are decoded too and listed in
`analysis.qr_codes` with `used_as`: a link QR is analysed as one of the screenshot's links
(`found_in: "qr"`); the first UPI QR adds its UPI indicators, and a UPI QR next to "receive money /
prize / refund" text adds `QR_UPI_RECEIVE_CONTEXT` (+30, floor 60), because **scanning a UPI QR
always sends money, it never receives it**. A screenshot with a QR code but no text is analysed as a
QR code.

### `POST /api/generate/qr` ✅ implemented
Utility only, separate from analysis. Payloads are **not** logged and **not** stored. The apps can
also generate codes locally.
```json
{ "type": "wifi", "data": { "ssid": "HomeNet", "password": "correcthorse1", "security": "WPA2" }, "format": "png", "size": 512 }
```

| `type` | `data` fields |
|---|---|
| `text` | `text` (1–1000 chars) |
| `url` | `url` (complete `http://` or `https://` address; other schemes rejected) |
| `wifi` | `ssid` (1–32), `password` (WPA/WPA3: 8–63), `security` (`WPA`, `WPA2`, `WPA3`, `WEP`, `nopass`), `hidden` (`"true"`/`"false"`) |
| `email` | `to`, optional `subject` (≤ 200), `body` (≤ 1000) |
| `phone` | `number` (digits, spaces, `+`, `-`, brackets) |

`format` ∈ `png | svg`. Real response (image shortened):
`{ "request_id": "…", "type": "wifi", "payload": "WIFI:T:WPA;S:HomeNet;P:***;;", "format": "png", "mime": "image/png", "image_base64": "iVBORw0KGgoA…" }`.
SVG responses carry `svg` instead of `image_base64`. Special characters (`\ ; , : "`) in Wi-Fi fields
are escaped as the Wi-Fi QR format requires; the password appears only inside the image, never in
`payload`. Unknown fields or invalid values → `400 VALIDATION_ERROR`. Limit: 30/min.

### Sign-in, history, reports, admin ✅ implemented

**Authentication.** Send `Authorization: Bearer <Firebase ID token>` (the apps use Firebase
anonymous or e-mail sign-in). The backend verifies the token with the Firebase Admin SDK
(signature, expiry, audience = our project). On the analysis endpoints the header is optional, but a
header that is present must be valid (`401 INVALID_TOKEN` otherwise). Signed-in users are
rate-limited per uid (`RATELIMIT_ANALYZE_AUTH`, 40/min) instead of per IP (20/min).

| Status | `code` | When |
|---|---|---|
| 401 | `AUTH_REQUIRED` | No token on a protected route |
| 401 | `INVALID_TOKEN` | Malformed, expired, revoked or foreign token |
| 403 | `FORBIDDEN` | Admin route without the custom claim `admin: true` |
| 404 | `NOT_FOUND` | Scan or report does not exist **for this user** (other users' ids look the same) |
| 503 | `SERVICE_UNAVAILABLE` | Firebase / history not configured on this server, or tokens cannot be checked right now |

**Saving a scan.** Add `"save_to_history": true` (form field `"true"` for uploads) to any analysis
request. The response then contains a `history` block; the analysis itself never fails because of
history:

```json
"history": { "saved": true, "scan_id": "ToQ2mX0c1vPq9aZr8LkE" }
"history": { "saved": false, "reason": "sign_in_required" | "history_disabled" | "history_unavailable" | "history_error" }
```

Only the verdict is stored (docs/database-design.md): score, level, confidence, verification,
categories, indicator ids/titles/severity/points, recommendation, threat-intel statuses and a
minimised `target`. **Never** the message, OCR text, image, QR payload, Wi-Fi password, indicator
evidence or full URL.

| `input_type` | `target` |
|---|---|
| `url`, link QR codes | `{ "kind": "url", "domain": "sbi-kyc-update.xyz", "url_hash": "<sha256 of the normalised URL>" }` |
| `message`, `screenshot` | `{ "kind": "message", "length": 149, "url_count": 1 }` |
| `qr_camera` / `qr_image` with UPI | `{ "kind": "upi", "payee_domain": "@okdemo" }` |
| other QR content | `{ "kind": "wifi" }` etc. |

#### `GET /api/history?limit=20&cursor=<scanId>` (auth)
Newest first. `limit` 1–50; `next_cursor` is `null` on the last page.
```json
{ "items": [ { "id": "ToQ2…", "input_type": "url", "created_at": "2026-09-29T14:20:11.512+00:00",
               "risk_score": 70, "risk_level": "MALICIOUS", "confidence": "HIGH",
               "verification": { "status": "UNVERIFIED", "source": null }, "categories": ["phishing"],
               "indicators": [ { "id": "BRAND_IN_DOMAIN_NAME", "title": "…", "severity": "high", "score_contribution": 22.5, "source": "link" } ],
               "recommended_action": "…", "target": { "kind": "url", "domain": "sbi-kyc-update.xyz", "url_hash": "9f2c…" },
               "threat_intel": [ { "provider": "local_feed", "status": "not_listed" } ], "engine_version": "0.1.0" } ],
  "next_cursor": null }
```

#### `GET /api/history/{scan_id}` (auth) → one item · `DELETE /api/history/{scan_id}` (auth) → `204`
#### `DELETE /api/history` (auth) → `200 { "deleted": 37 }`

#### `GET /api/me` · `PATCH /api/me` · `DELETE /api/me` (auth)
`GET` → `{ "uid": "…", "is_anonymous": true, "admin": false, "save_history": true, "history_retention_days": 90 }`.
`PATCH` `{ "save_history": false }` switches saving off (later requests answer
`history_disabled`). `DELETE` ("delete my data") removes all scans, removes the uid from the user's
reports, deletes the settings and the Firebase account:
`{ "deleted_scans": 12, "anonymised_reports": 1, "account_deleted": true }`.

#### `POST /api/reports` (auth, 10/min)
`{ "reported_as": "false_positive" | "false_negative" | "scam", "note": "≤ 280 chars", "scan_id": "optional, one of your scans" }`
→ `201 { "id": "…" }`. With `scan_id`, the report copies only that scan's `domain`/`url_hash`.

#### Admin (custom claim `admin: true`, checked by the backend)
- `GET /api/admin/stats?days=30` (1–90) → `{ "days": [ { "date": "2026-09-29", "total": 431, "by_level": { "SAFE": 300, … }, "by_type": { "url": 120, … }, "ti_unavailable": 3 } ], "threat_intel": [ { "provider": "urlhaus", "enabled": false, "external": true }, … ] }`.
  Daily counters are anonymous (they include anonymous analyses; no user ids).
- `GET /api/admin/reports?status=open|reviewed` → `{ "items": [ { "id", "scan_id", "reported_as", "domain", "url_hash", "note", "status", "created_at" } ] }` (the reporter's uid is not shown).
- `PATCH /api/admin/reports/{id}` `{ "status": "reviewed" }` → `{ "id": "…", "status": "reviewed" }`.

## 4. Limits (configurable via env)

| Limit | Default |
|---|---|
| JSON body | 64 KB |
| Upload | 5 MB, ≤ 25 megapixels |
| URL length | 2048 |
| Message length | 5000 chars |
| Rate limit, anonymous | 20/min, 200/day per IP |
| Rate limit, authenticated | 40/min, 500/day per uid |
| `/api/analyze/screenshot` | additional `RATELIMIT_SCREENSHOT` = 6/min, 60/day (CPU-heavy OCR); OCR timeout 20 s, max 2 concurrent OCR jobs per process |
| Threat-intel time budget | `THREAT_INTEL_BUDGET_SECONDS` = 6 s total, `THREAT_INTEL_TIMEOUT_SECONDS` = 3 s per provider request; VirusTotal max 4 lookups/min per process; cache 24 h (listed) / 1 h (not listed) |
| Redirect checking | `REDIRECT_RESOLUTION=shorteners_only`, max 5 redirects, 3 s per request, 8 s total, ports 80/443 only, 0 body bytes read |

## 5. CORS

`ALLOWED_ORIGINS` is a comma-separated list, e.g.
`https://qrguard.vercel.app,http://localhost:5173`. The only methods allowed are
`GET, POST, DELETE, PATCH, OPTIONS`, and the only headers are `Authorization, Content-Type`.
Native mobile requests are not subject to CORS.
