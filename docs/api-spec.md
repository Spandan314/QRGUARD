# REST API Specification (v1 contract)

- **Base URL:** `https://<render-service>.onrender.com` (local: `http://localhost:5000`)
- **Format:** JSON (UTF-8), except uploads, which use `multipart/form-data`.
- **Auth:** `Authorization: Bearer <Firebase ID token>`. This is **optional** for analysis (anonymous
  callers get stricter rate limits and no history) and **required** for history, reports and admin.
- **Versioning:** the paths below are frozen for v1. Breaking changes need a new prefix (`/api/v2`).
  Every response carries `engine_version`.

## 1. Common result object (`AnalysisResult`)

Returned by all four `/api/analyze/*` endpoints.

```json
{
  "request_id": "b7c1e0f2a9",
  "input_type": "url",
  "risk_score": 67,
  "risk_level": "SUSPICIOUS",
  "confidence": "MEDIUM",
  "summary": "This link shows several warning signs commonly seen in phishing.",
  "indicators": [
    {
      "id": "URL_SHORTENER",
      "category": "url_structure",
      "severity": "medium",
      "weight": 10,
      "title": "Link uses a URL shortener",
      "explanation": "Shortened links hide the real destination.",
      "evidence": "bit.ly"
    },
    {
      "id": "URL_NO_HTTPS",
      "category": "url_structure",
      "severity": "low",
      "weight": 8,
      "title": "Link does not use HTTPS",
      "explanation": "Data sent to this site is not encrypted.",
      "evidence": "http://"
    }
  ],
  "score_breakdown": { "url_structure": 18, "lexical": 12, "brand": 25, "host": 0, "reputation": 0, "message": 0, "qr": 0, "combination_bonus": 12 },
  "threat_intel": [
    { "provider": "local_feed", "status": "not_listed" },
    { "provider": "urlhaus", "status": "not_listed" },
    { "provider": "google_safe_browsing", "status": "unavailable", "detail": "timeout" },
    { "provider": "virustotal", "status": "disabled" }
  ],
  "threat_intel_note": "Not being listed does not mean a link is safe.",
  "recommended_action": "Do not open the link or enter OTP/payment details. Verify via the official app or website.",
  "details": { },
  "disclaimer": "This is an automated security assessment, not a guarantee.",
  "engine_version": "0.1.0",
  "history_id": null
}
```

- `severity` ∈ `info | low | medium | high | critical`. `info` indicators have weight 0 and are
  explanatory only, e.g. "This QR makes a UPI payment".
- `threat_intel[].status` ∈ `listed | not_listed | unavailable | disabled | error`.
- `details` depends on the endpoint (below).

## 2. Common error object

```json
{ "error": { "code": "FILE_TOO_LARGE", "message": "Image must be 5 MB or smaller.", "request_id": "b7c1e0f2a9" } }
```

| HTTP | `code` examples | When |
|---|---|---|
| 400 | `INVALID_JSON`, `VALIDATION_ERROR`, `INVALID_URL`, `NO_QR_FOUND` | Bad input |
| 401 | `AUTH_REQUIRED`, `INVALID_TOKEN` | Missing or expired token on protected routes |
| 403 | `FORBIDDEN` | Not an admin, or not the owner |
| 404 | `NOT_FOUND` | Unknown route or scan ID |
| 405 | `METHOD_NOT_ALLOWED` | |
| 413 | `FILE_TOO_LARGE`, `PAYLOAD_TOO_LARGE` | Above `MAX_UPLOAD_MB` or the JSON limit |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Not PNG/JPEG/WEBP, or wrong Content-Type |
| 422 | `UNPROCESSABLE_IMAGE`, `OCR_FAILED` | Corrupt image, OCR produced nothing |
| 429 | `RATE_LIMITED` | Includes a `Retry-After` header |
| 500 | `INTERNAL_ERROR` | Generic message only. The stack trace goes to server logs, never to the client. |
| 503 | `SERVICE_UNAVAILABLE` | e.g. history requested but Firebase is not configured |

## 3. Endpoints

### `GET /api/health`
Public. No rate limit beyond the global one.
```json
{ "status": "ok", "engine_version": "0.1.0", "time": "2026-09-29T10:00:00Z",
  "components": { "ocr": "ok", "firebase": "ok", "threat_intel": { "local_feed": "enabled", "urlhaus": "enabled", "google_safe_browsing": "enabled", "virustotal": "disabled", "phishtank": "disabled" } } }
```

### `POST /api/analyze/url`
Request:
```json
{ "url": "http://bit.ly/demo-test", "save_to_history": true }
```
Rules: `url` must be a string of 1–2048 characters. A missing scheme is treated as `http://`
(reported as an indicator). Only `http`/`https` are analysed as web links. `javascript:`, `data:`,
`file:` and `intent:` are rejected as **MALICIOUS-by-scheme** results, not errors.

`details`:
```json
{ "original_url": "http://bit.ly/demo-test", "normalized_url": "http://bit.ly/demo-test",
  "scheme": "http", "host": "bit.ly", "registrable_domain": "bit.ly", "tld": "ly",
  "redirect_chain": [{ "url": "http://bit.ly/demo-test", "status": 301 }, { "url": "https://example.com/", "status": 200 }],
  "final_url": "https://example.com/", "redirect_resolution": "performed",
  "domain_age_days": null, "domain_age_status": "unavailable" }
```

### `POST /api/analyze/message`
```json
{ "text": "Dear customer your SBI account will be BLOCKED today. Update KYC: http://sbi-kyc.example/login", "save_to_history": false }
```
Rules: `text` has 1–5000 characters. Control characters are stripped. The text is **not logged and
not stored**.

`details`:
```json
{ "scam_types": [{ "type": "kyc_banking", "score": 55 }],
  "matched_phrases": [{ "category": "threat", "phrase": "account will be BLOCKED" }, { "category": "urgency", "phrase": "today" }],
  "urls": [ { "url": "http://sbi-kyc.example/login", "risk_score": 70, "risk_level": "MALICIOUS", "indicators": [ ] } ],
  "phone_numbers": [], "language": "en" }
```

### `POST /api/analyze/screenshot`
`multipart/form-data`: `file` (PNG/JPEG/WEBP, ≤ 5 MB, ≤ 25 MP), plus the optional form field `save_to_history`.

`details`:
```json
{ "extracted_text": "Congratulations! You have won …", "ocr_confidence": 81.4, "ocr_quality": "good",
  "urls": [ ], "qr_codes": [ ], "matched_phrases": [ ] }
```
`extracted_text` is returned to the caller only. It is never stored or logged.

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
| `/api/analyze/screenshot` | additional 6/min (CPU-heavy OCR) |
| Threat-intel time budget | 6 s total, 3 s per provider |
| Redirect resolution | max 5 hops, 3 s per hop, ports 80/443 only |

## 5. CORS

`ALLOWED_ORIGINS` is a comma-separated list, e.g.
`https://qrguard.vercel.app,http://localhost:5173`. The only methods allowed are
`GET, POST, DELETE, PATCH, OPTIONS`, and the only headers are `Authorization, Content-Type`.
Native mobile requests are not subject to CORS.
