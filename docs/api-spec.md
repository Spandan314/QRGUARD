# REST API Specification (v1 contract)

- **Base URL:** `https://<render-service>.onrender.com` (local: `http://localhost:5000`)
- **Format:** JSON (UTF-8), except uploads, which use `multipart/form-data`.
- **Auth:** `Authorization: Bearer <Firebase ID token>`. This is **optional** for analysis (anonymous
  callers get stricter rate limits and no history) and **required** for history, reports and admin.
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
    "checked": false,
    "providers": [],
    "note": "Threat-intelligence lookups are not enabled yet; this result is based on the link's structure only."
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
                  "ocr_engine": "available" } }
```

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
- `save_to_history` is accepted now and used once history is implemented.

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
  "threat_intel": { "checked": false, "providers": [], "note": "Threat-intelligence lookups are not enabled yet; links were analysed by their structure only." },
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
| `save_to_history` | no | `"true"` or `"false"` (used once history exists) |

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
- QR codes inside screenshots are not detected yet (QR phase).

### `POST /api/analyze/qr`
Two accepted forms:

1. JSON (camera scan, already decoded on device): `{ "content": "upi://pay?pa=abc@okaxis&pn=Shop&am=4999", "source": "camera", "save_to_history": true }` (`content` ≤ 4096 chars)
2. Multipart: `file` = QR image (same limits as screenshot).

`details`:
```json
{ "decoded_content": "upi://pay?pa=abc@okaxis&pn=Shop&am=4999",
  "content_type": "upi",
  "parsed": { "payee_vpa": "abc@okaxis", "payee_name": "Shop", "amount": "4999", "currency": "INR", "note": null },
  "url_analysis": null }
```
`content_type` ∈ `url | upi | wifi | email | phone | sms | geo | vcard | text | other`.

### `POST /api/generate/qr`
Utility only. It is **not** logged and **not** stored. Clients normally generate locally.
```json
{ "type": "wifi", "data": { "ssid": "HomeNet", "password": "…", "security": "WPA" }, "format": "png", "size": 512 }
```
`type` ∈ `text | url | wifi | email | phone`. Response:
`{ "payload": "WIFI:T:WPA;S:HomeNet;P:…;;", "mime": "image/png", "image_base64": "iVBOR…" }`.
Special characters (`\ ; , : "`) in Wi-Fi fields are escaped as the Wi-Fi QR format requires.

### `GET /api/history?limit=20&cursor=<scanId>` (auth)
```json
{ "items": [ { "id": "aB3…", "input_type": "url", "created_at": "…", "risk_score": 67, "risk_level": "SUSPICIOUS",
               "confidence": "MEDIUM", "indicators": [ ], "recommended_action": "…", "target": { "kind": "url", "domain": "bit.ly" } } ],
  "next_cursor": "Zx9…" }
```
`limit` is between 1 and 50.

### `DELETE /api/history/{scan_id}` (auth) → `204`
### `DELETE /api/history` (auth) → `200 { "deleted": 37 }`
### `POST /api/reports` (auth)
`{ "scan_id": "aB3…", "reported_as": "false_positive", "note": "This is my bank's real domain" }` → `201 { "id": "…" }`
### `GET /api/admin/stats?days=30` (admin) → daily aggregates
### `GET /api/admin/reports?status=open` (admin) · `PATCH /api/admin/reports/{id}` `{ "status": "reviewed" }` (admin)

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
| Threat-intel time budget | 6 s total, 3 s per provider (when providers are added) |
| Redirect checking | `REDIRECT_RESOLUTION=shorteners_only`, max 5 redirects, 3 s per request, 8 s total, ports 80/443 only, 0 body bytes read |

## 5. CORS

`ALLOWED_ORIGINS` is a comma-separated list, e.g.
`https://qrguard.vercel.app,http://localhost:5173`. The only methods allowed are
`GET, POST, DELETE, PATCH, OPTIONS`, and the only headers are `Authorization, Content-Type`.
Native mobile requests are not subject to CORS.
