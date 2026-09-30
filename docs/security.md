# Security Design (controls overview)

Summary of the security controls. Every control below is implemented and covered by tests; the
sections after the table give the implementation details, and the last section records the security
audit.

| Control | Design | Why |
|---|---|---|
| HTTPS | Render and Vercel terminate TLS. The backend sets `Strict-Transport-Security`. The mobile production build only uses an `https://` API URL. | Protects tokens and inputs in transit |
| Authentication | Firebase ID token verified server-side with `firebase_admin.auth.verify_id_token` (checks signature, expiry, audience). `@optional_auth` on analysis, `@require_auth` on history/reports. | Stops clients from forging identities |
| Authorization | History queries always use the **token's** uid, never a uid from the request. Admin needs the `admin` custom claim, checked on the server. | Prevents IDOR and privilege escalation |
| Input validation | Pydantic models, length limits, type checks. Control characters stripped. Unknown fields rejected. | Rejects malformed and oversized input early |
| File uploads | `MAX_CONTENT_LENGTH`. Extension **and** magic bytes checked (PNG/JPEG/WEBP only). `Image.verify()`. `Image.MAX_IMAGE_PIXELS` cap against decompression bombs. Processed in memory and never written to disk. EXIF ignored. | Blocks malicious or huge files |
| Rate limiting | Flask-Limiter: per IP for anonymous callers, per uid for signed-in ones, with a tighter limit on OCR | Protects CPU and third-party quotas from abuse |
| API key protection | Server secrets only in env/Render secrets. Keys never go into client bundles. `.env` is git-ignored. `gitleaks` runs in CI. | Stops key leakage |
| CORS | Explicit origin allowlist from `ALLOWED_ORIGINS`. No wildcard with credentials. | Stops other websites from calling the API with a user's session |
| SSRF protection | See "SSRF protection" below (implemented) | Stops the URL checker from being used as a proxy into internal networks |
| Redirect handling | Manual redirect loop, max 5 hops, every hop re-validated, IP pinning, no body read | Stops a redirect to `http://169.254.169.254/` |
| Logging | JSON logs with request_id, route, status and latency. **Never** raw message text, OCR text, full URLs (only domain and hash), tokens or keys. Newlines in values escaped. | Logs alone never expose user data |
| Error handling | Global handlers return the generic JSON error. `DEBUG=False` in production. Stack traces only in server logs. | Avoids leaking internals |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a CSP on the web app | Defence in depth for browsers |
| Firestore rules | Deny by default. Owner-only reads and deletes. No client writes to scans. | Protects data if the API is bypassed |
| Output safety | Web shows URLs as text (React escaping, no `dangerouslySetInnerHTML`). Mobile `OpenLinkGuard` blocks dangerous schemes. | No XSS, and no accidental navigation to the link being checked |
| ReDoS | Scam patterns are simple alternations with no nested quantifiers. Input is capped at 5000 chars. Rules are unit-tested for time. | Stops CPU exhaustion from crafted text |
| Dependencies | Pinned `requirements.txt` / lockfiles, Dependabot, `pip-audit` and `npm audit` in CI | Supply-chain hygiene |

## SSRF protection and safe redirect checking (implemented)

**Threat:** the URL checker takes attacker-controlled input. If the backend blindly fetched URLs,
an attacker could make it request `http://169.254.169.254/` (cloud credentials),
`http://localhost:5000/…` (internal services) or machines on a private network, and read the
results through our API.

**Design principle:** the backend contacts a link **only to learn where it redirects**, and by
default only for known link shorteners (`REDIRECT_RESOLUTION=shorteners_only`). All other analysis
is static (no network).

Implementation: `app/utils/net_safety.py` and `app/analyzers/redirect_resolver.py`.

| Requirement | How it is enforced |
|---|---|
| Only HTTP/HTTPS | Every hop's scheme is checked. `javascript:`, `data:`, `intent:`… stop the check and are reported (`REDIRECT_DANGEROUS_SCHEME`, floor 80). `upi:`, `ftp:`… stop it too (`REDIRECT_NON_WEB_SCHEME`). |
| Only standard ports | Ports 80 and 443 only. Links with other ports are never contacted. |
| Block localhost / 127.0.0.0/8 | `is_public_ip()` rejects loopback. Names `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.lan`, `*.home.arpa`… and single-label names are refused **before** DNS. |
| Block private IPv4 | 10/8, 172.16/12, 192.168/16, plus 100.64/10 (CGNAT), 0/8, 192.0.0/24, 198.18/15 |
| Block link-local | 169.254/16 (includes the cloud metadata address) and fe80::/10 |
| Block multicast / reserved | 224/4, 240/4, broadcast, `::`, ff00::/8, documentation ranges (everything not globally routable) |
| Block IPv6 loopback/private | ::1, fc00::/7, fe80::/10, NAT64 64:ff9b::/96, and **IPv4 hidden in IPv6** (`::ffff:127.0.0.1`, 6to4, Teredo) |
| Disguised IPs | `http://2130706433/`, `0x7f.1`, `0177.0.0.1` are decoded the way browsers do, then checked |
| Re-resolve DNS after redirects | Every hop resolves its host again, and **all** returned addresses must be public |
| DNS rebinding | The request connects to the **already-validated IP** (IP pinning) and sends the real hostname in `Host`/TLS SNI. The certificate is verified against the hostname. A second DNS answer cannot redirect the connection. |
| Validate every redirect destination | Each `Location` is joined to the current URL and re-checked from the first step (scheme, port, host, DNS, IP) |
| Limit redirect count | `REDIRECT_MAX_HOPS` (default 5); more → `REDIRECT_CHAIN_TOO_LONG` |
| Limit response size | Response bodies are **never read** (0 bytes; `preload_content=False`, connection closed). Only the status code and `Location` header (≤ 2048 characters) are used. |
| Strict timeouts | DNS, connect and read each ≤ `REDIRECT_TIMEOUT_SECONDS` (3 s), and the whole check ≤ `REDIRECT_TOTAL_TIMEOUT_SECONDS` (8 s). No retries. |
| No execution of downloaded content | Nothing is downloaded, stored, parsed or executed. `HEAD` is used; `GET` only if the server refuses `HEAD`, and its body is still not read. |
| No internal exposure | Resolved IP addresses are never included in API responses or error messages. Blocked targets are reported only as `blocked_private_address`. |
| Fail safe | DNS failures, timeouts, TLS and connection errors are reported as statuses, and confidence drops. The analysis still completes and never crashes. |

**Residual risks (documented honestly):**
- Following a link is itself a visit: it can confirm to a scammer that the link was opened, or
  consume a one-time token. That is why only shorteners are followed by default, and why
  `REDIRECT_RESOLUTION=off` exists.
- Only HTTP 3xx redirects are followed. JavaScript or `<meta refresh>` redirects inside a page are
  not detected, because we never read page content.
- `resolve_host` uses the server's system DNS resolver; the DNS answer is trusted only after the
  public-IP check.

## URL input handling (implemented)

- Pydantic validation: string, 1–2048 characters, unknown fields rejected.
- Control characters are rejected, and tabs/newlines removed (as browsers do). Hosts are converted
  with IDNA/UTS-46 and each label is validated. Invalid input → `400 INVALID_URL`.
- The public-suffix split uses the list **bundled** with `tldextract` (no network download at runtime).
- The normalised URL masks any password (`user:***@host`) and drops the `#fragment`.
- Rule files (`app/data/*.yaml`) and `scoring_config.yaml` are loaded with `yaml.safe_load` and
  strictly validated at startup.

## Scam-message analysis (implemented)

| Concern | Control |
|---|---|
| Privacy of message text | The text is never logged (the access log records only method, path, status and duration; a test checks this with `caplog`) and never stored. The response returns only short matched phrases (≤ 60 characters), with amounts, UPI IDs, e-mails and links replaced by markers. Phone numbers are masked (`******3210`). |
| ReDoS (regex denial of service) | Patterns are validated at startup: anything with a nested quantifier such as `(a+)+` is rejected. The "words in between" gap is a fixed, bounded construct (`\W+(?:\w+\W+){0,4}?`). Matching runs per sentence on at most 5000 characters. Tests check that adversarial inputs (5000 × "!", "share share …", one huge link) finish in well under 0.5 s. |
| Abuse through links in messages | At most 3 links are analysed and at most 2 redirect checks made per message. Every check goes through the same SSRF-protected redirect checker as `/api/analyze/url`. |
| Obfuscation | Invisible characters, full-width/styled letters, look-alike letters, leetspeak and defanged links (`hxxp`, `[.]`) are normalised before matching, and their presence is reported. |
| Rule-file tampering / mistakes | `scam_rules.yaml` is loaded with `yaml.safe_load` and strictly validated (unknown keys, bad IDs, invalid regex, unknown combination members → startup error). |

## Screenshot uploads and OCR (implemented)

| Concern | Control |
|---|---|
| Wrong / dangerous file types | The type is detected from the **file content** (magic bytes + Pillow header). Only PNG, JPEG and WEBP are accepted, and the extension is ignored. GIF, PDF, SVG, scripts and executables → 415. |
| Oversized uploads | `MAX_CONTENT_LENGTH` (5 MB) rejects the request before it is read. The route reads at most limit + 1 bytes. |
| Decompression bombs / huge images | Dimensions are read from the header **before decoding**: max 10000 px per side and 25 MP (`MAX_IMAGE_MEGAPIXELS`). Pillow's `DecompressionBombWarning` is treated as an error. |
| Malformed / truncated images | `Image.verify()` plus a full decode. Failures → 422 `UNPROCESSABLE_IMAGE`. OCR never runs on rejected files. |
| Temporary files / path traversal | None exist: the upload is kept in memory, Tesseract receives the image on **stdin** and returns text on stdout, and the uploaded filename is never used or returned. |
| Executing uploads | Nothing is executed. Tesseract is started with a fixed argument list (no shell) and only reads image data. |
| Resource exhaustion | OCR timeout (`OCR_TIMEOUT_SECONDS`, 20 s), at most `OCR_MAX_CONCURRENT` (2) OCR jobs per process (then 503 `OCR_BUSY`), single-threaded Tesseract (`OMP_THREAD_LIMIT=1`), stricter rate limit (`RATELIMIT_SCREENSHOT`, 6/min), images downscaled to ≤ 4000 px for OCR. |
| Privacy | Screenshots and OCR text are never written to disk, logged or stored. `extracted_text` is returned only to the caller. Error messages never include OCR text, Tesseract output or file paths. A test checks logs and the temp directory. |
| Link safety | Links read from screenshots go through the same SSRF-protected URL analyzer as `/api/analyze/url`, with the same per-message limits (3 links analysed, 2 redirect checks). |

## QR decoding and generation (implemented)

| Concern | Control |
|---|---|
| Malicious QR images | Same in-memory validation as screenshots (content-type sniffing, size/pixel caps, decompression-bomb check, full decode) before OpenCV sees the image. Images are downscaled to ≤ 2000 px for decoding. OpenCV errors are caught and reported as "no QR code found", never as a 500 with internals. |
| Oversized / many payloads | At most 5 codes per image are analysed; a payload over 4096 characters is ignored (JSON `content` is limited to 4096). |
| Acting on content | QRGUARD never opens, dials, pays, sends or connects to anything in a QR code. Web links go through the SSRF-protected URL analyzer (only shortener redirects are checked, no body read); `javascript:`, `data:`, `intent:` and similar schemes are flagged, never followed. |
| Wi-Fi passwords | Never returned: `decoded_content` shows `P:***`, `parsed` has only `has_password`. The generator returns the payload with the password masked (it exists only inside the image). Tests check responses **and logs**. |
| Privacy | Decoded content is returned to the caller only, never logged or stored. Parsing errors never echo the content. |
| Generator abuse | Strict per-type field allow-list (unknown fields → 400), length limits, `http(s)` only for URLs (a `javascript:` code cannot be generated), Wi-Fi special characters escaped, limit 30/min. |

## Threat intelligence (implemented)

| Concern | Control |
|---|---|
| API keys | Only from environment variables (never in code, docs, Postman or fixtures). Format-checked at startup with an error that never shows the value; excluded from the Config `repr` and provider `repr`; never logged, never in responses or `/api/health` (which shows only on/off). Tests check responses, health, logs and repr with fake keys. |
| Keys inside error text | The HTTP client re-raises network errors `from None`, so exception text that contains the request URL (Safe Browsing puts its key in the query string) can never reach logs or responses. |
| Data sent to providers | Only the normalised URL (VirusTotal: its base64 URL id). Never message/OCR text, IP addresses, user ids or request ids. Local feeds (default) send nothing. VirusTotal is lookup-only: URLs are never submitted. |
| SSRF | Providers contact only fixed, hard-coded HTTPS endpoints with certificate verification, no redirects and no retries. User input only appears in the request body/path, never as the host. |
| Availability | Per-request timeout (3 s), overall budget (6 s), parallel lookups; a slow, failing or crashing provider becomes `unavailable` and local analysis continues. A 1 MB response cap prevents memory abuse. The VirusTotal guard (4 lookups/min) avoids quota bans. |
| Integrity of verdicts | Malformed or unexpected answers become `unavailable`, never `not_listed`. `not_listed` never lowers a score; one confirmed `listed` is enough (floor 90). |
| Feed files | Loaded at startup only, 50 MB cap per file, unparseable lines skipped. `ti-update-feeds` downloads only the two fixed feed URLs, caps size and writes atomically. The demo list holds only reserved `.example`/`.test` names. |
| Privacy of results | The cache key is a SHA-256 of provider + URL (no clear-text URLs), in memory only, with TTLs. URLs are not logged by TI code. |

## Sign-in, history, reports and admin (implemented)

| Concern | Control |
|---|---|
| Identity | Firebase ID tokens verified on the server (`firebase_admin.auth.verify_id_token`: signature, expiry, audience = project, issuer). Malformed/expired/revoked/foreign → `401 INVALID_TOKEN`; Google's keys unreachable → `503`. Tokens over 4096 chars are rejected. Tokens are never logged. |
| Access control (IDOR) | Every history query uses the **token's** uid (`users/{uid}/scans`), never an id from the request; another user's scan id is simply `404`. Scan and report ids are validated against a strict pattern before use. Tests cover cross-user read and delete. |
| Admin | Custom claim `admin: true` (set only with the Admin SDK, never from a client-writable document), checked by `@require_admin` on the server; the claim must be exactly `true`. Admin endpoints expose only anonymous daily counters and reports **without** the reporter's uid. |
| Score forgery | Only the backend writes scans (Admin SDK). Firestore rules deny client create/update on `scans`, `reports`, `stats_daily` and everything else; a user may only read/delete their own scans and change `save_history` (typed bool) on their own settings. Rules are tested in the Firestore emulator (`firebase/tests/rules.test.js`). |
| Data minimisation | Scans store verdicts only: no message/OCR text, images, QR payloads, Wi-Fi passwords, indicator evidence or full URLs (domain + SHA-256 hash; UPI: provider suffix only). Tests search saved records for fragments of the submitted content. |
| Retention and deletion | `expire_at` = +90 days (`HISTORY_RETENTION_DAYS`) for a Firestore TTL policy; delete one scan, all scans, or everything (`DELETE /api/me`: scans, report uid, settings, Firebase account). |
| Availability | History/statistics failures are logged without content and never fail the analysis. Without Firebase, analysis works and protected routes answer `503`. |
| Rate limits | Per uid for signed-in users (40/min), per IP otherwise (20/min); reports 10/min. An invalid token falls back to the IP key. |
| Credentials | `FIREBASE_CREDENTIALS_JSON` / `FIREBASE_CREDENTIALS_FILE` only from the environment, excluded from the Config `repr`; an invalid key is reported without its content. |
| Demo/test mode | `AUTH_DEV_TOKENS=true` ("dev-<uid>" tokens) and `HISTORY_STORE=memory` exist for local demos and automated API tests without a Firebase project. **Startup fails** if either is set with `APP_ENV=production`. |


## Security audit (Phase 11, 2026-09-29)

| Check | How | Result |
|---|---|---|
| Python dependencies | `pip-audit -r backend/requirements.txt` | No known vulnerabilities |
| Web dependencies | `npm audit` in `web/` | 0 vulnerabilities |
| Mobile dependencies | `npm audit --omit=dev` in `mobile/` | 14 moderate, see below |
| Firebase tooling | `npm audit` in `firebase/` | 5 moderate in `firebase-tools` (a developer CLI for emulators and deploys; never shipped or run in production) |
| E2E tooling | `npm audit` in `e2e/` | 0 vulnerabilities |
| Secrets in git history | pattern scan of `git log --all -p` (Google API keys, private keys, GitHub/AWS/Slack tokens) and tracked `.env`/key/keystore files | None. The only match is a fake `"private_key": "SUPERSECRET"` test fixture that checks the value is never echoed |
| Secrets in app bundles | scan of the web build and the Expo web export for provider key names, `private_key`, service-account fields | None. The frontends contain only public `VITE_*` / `EXPO_PUBLIC_*` values and never call threat-intelligence providers |
| CORS | production container with `ALLOWED_ORIGINS=https://<web>`: the listed origin gets `Access-Control-Allow-Origin`; a foreign origin gets no CORS header; `*` refused at start-up in production | Pass |
| Production guards | container with `APP_ENV=production AUTH_DEV_TOKENS=true` | Refuses to start |
| Auth and isolation | production container + Firebase emulators with real ID tokens: dev tokens rejected, user B cannot see user A's history, non-admin gets 403 on `/api/admin/*` | Pass |
| Logs | backend logs after the full E2E run (URLs, messages, a camera QR, sign-ins) searched for tokens (`eyJ…`), message text, URLs and QR payloads | None found (`e2e/run.sh` fails if any appear) |
| Exception logging | Final audit: unhandled-error logs keep stack frames and exception **types** only; exception messages (which a library may fill with the submitted URL, text or QR payload) are withheld | Fixed and tested (`tests/unit/test_logging.py`) |
| Storage minimisation | history records hold domain + SHA-256 URL hash, message length / link count, UPI payee domain; no text, OCR output, screenshots or full QR payloads | Verified by `tests/integration/test_api_history.py` and the E2E history checks |

**Mobile advisories (accepted, reviewed).** All 14 come from two packages:

- `decode-uri-component` ≤ 0.4.2 (via `expo-router` → `query-string@7`): a denial-of-service with
  malformed percent-encoded input. It runs only on the user's own phone when the router parses an
  in-app URL, so the worst case is that the user's own app hangs; the backend is not affected.
  The patched 0.5.x line is ESM-only and cannot be forced under `query-string@7` without breaking
  navigation.
- `uuid` < 11.1.1 (via `@expo/config-plugins` → `xcode`): a bounds-check bug when a caller
  passes its own buffer. It is used only by build tooling that generates native project files, not
  in the app at runtime.

`npm audit fix --force` would downgrade to Expo SDK 46, which is not an acceptable fix. Re-check
these on each Expo SDK upgrade.
