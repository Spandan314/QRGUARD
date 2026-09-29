# Security Design (controls overview)

This is the design-level summary. Each control is implemented and tested in a later phase, and
Phase 10 expands this into the report chapter.

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
| SSRF protection | See below | Stops the URL checker from being used as a proxy into internal networks |
| Redirect handling | Manual redirect loop (`allow_redirects=False`), max 5 hops, every hop re-validated, no body read | Stops a redirect to `http://169.254.169.254/` |
| Logging | JSON logs with request_id, route, status and latency. **Never** raw message text, OCR text, full URLs (only domain and hash), tokens or keys. Newlines in values escaped. | Logs alone never expose user data |
| Error handling | Global handlers return the generic JSON error. `DEBUG=False` in production. Stack traces only in server logs. | Avoids leaking internals |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a CSP on the web app | Defence in depth for browsers |
| Firestore rules | Deny by default. Owner-only reads and deletes. No client writes to scans. | Protects data if the API is bypassed |
| Output safety | Web shows URLs as text (React escaping, no `dangerouslySetInnerHTML`). Mobile `OpenLinkGuard` blocks dangerous schemes. | No XSS, and no accidental navigation to the link being checked |
| ReDoS | Scam patterns are simple alternations with no nested quantifiers. Input is capped at 5000 chars. Rules are unit-tested for time. | Stops CPU exhaustion from crafted text |
| Dependencies | Pinned `requirements.txt` / lockfiles, Dependabot, `pip-audit` and `npm audit` in CI | Supply-chain hygiene |

## SSRF guard (used by the redirect resolver and domain-age lookup)

1. Only `http` and `https` are allowed. The port must be 80 or 443.
2. Resolve the hostname (`getaddrinfo`). **Every** resolved address must pass `is_public_ip()`, which
   rejects private, loopback, link-local (including cloud metadata `169.254.169.254`), multicast,
   reserved, unspecified, CGNAT `100.64/10`, IPv6 ULA and IPv4-mapped forms.
3. Connect to the **validated IP** with the original `Host` header / SNI (IP pinning). This defeats
   DNS rebinding between the check and the connect.
4. `HEAD` first, falling back to `GET` with `stream=True`. The body is closed immediately. 3 s timeout.
   `User-Agent: QRGUARD-LinkCheck`.
5. On a redirect, the `Location` header is resolved against the current URL and **re-validated from
   step 1**.
6. Default mode is `REDIRECT_RESOLUTION=shorteners_only`. Following a link can itself notify the
   attacker (e.g. burning a one-time tracking token), so we only do it where it adds real value.
