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
| 422 | `UNPROCESSABLE_IMAGE`, `OCR_FAILED` | Corrupt image, OCR produced nothing |
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

### `POST /api/analyze/message`
```json
{ "text": "Dear customer your SBI account will be BLOCKED today. Update KYC: http://sbi-kyc.example/login", "save_to_history": false }
```
Rules: `text` has 1–5000 characters. Control characters are stripped. The text is **not logged and
not stored**.

`details`:
```json
{ "matched_categories": ["kyc_account_suspension", "impersonation", "malicious_url"],
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
| Threat-intel time budget | 6 s total, 3 s per provider (when providers are added) |
| Redirect checking | `REDIRECT_RESOLUTION=shorteners_only`, max 5 redirects, 3 s per request, 8 s total, ports 80/443 only, 0 body bytes read |

## 5. CORS

`ALLOWED_ORIGINS` is a comma-separated list, e.g.
`https://qrguard.vercel.app,http://localhost:5173`. The only methods allowed are
`GET, POST, DELETE, PATCH, OPTIONS`, and the only headers are `Authorization, Content-Type`.
Native mobile requests are not subject to CORS.
