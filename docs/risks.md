# Major Technical Risks and Security Risks

## 1. Technical risks

| # | Risk | Likelihood / Impact | Mitigation |
|---|---|---|---|
| T1 | **OCR quality** on real screenshots (dark mode, emojis, small fonts, compression) | High / High | Preprocessing (grayscale, 2× upscale, invert dark mode, Otsu threshold). Report OCR confidence and lower result confidence. Show extracted text so the user can check it. Let the user paste text into the message checker instead. |
| T2 | **Render free tier** limits: 512 MB RAM, cold starts, slow Docker builds | High / Medium | `opencv-python-headless`, 2 workers × 4 threads, no ML models. Warm up before the demo, or use a paid instance for demo week. Deploying in Week 2 exposes this early. |
| T3 | **Threat-intel availability and terms change** (PhishTank closed signups, URLhaus now needs a key, VT quotas) | High / Medium | Pluggable providers, local feeds first, graceful degradation, statuses shown honestly. Re-verify terms in Week 7. |
| T4 | **False positives on genuine messages** (real bank SMS mention OTP, "blocked card", links) | High / High | Negation and warning-phrase handling, combination-based scoring, category caps, a trusted-domain list, a labelled genuine-message set in tests. |
| T5 | **False negatives** on novel scams (rule-based limits) | High / Medium | State it as a limitation. User reports feed rule updates. ML is future scope. |
| T6 | **Expo SDK / library version churn** (camera API changes between SDKs) | Medium / Medium | Pin the Expo SDK at project creation and upgrade only deliberately. Use Expo's recommended package versions (`npx expo install`). |
| T7 | **Integration drift** between four members | Medium / High | Frozen API contract, mocks, CI, weekly integration, CODEOWNERS on shared contracts. |
| T8 | **No labelled evaluation data** → nothing credible for "Results" | Medium / High | Start `demo-data` in Week 3. Target ≥ 150 labelled items across types. Report precision/recall honestly, including failures. |
| T9 | Registrable-domain parsing mistakes (e.g. `.co.in`) | Medium / Medium | `tldextract` with the bundled suffix list, plus unit tests for Indian ccTLD cases |
| T10 | Firebase config/credentials mishandled on Render | Medium / Medium | Secret File + `GOOGLE_APPLICATION_CREDENTIALS`. The backend runs in "history disabled" mode (not crash) if it is missing. |
| T11 | Team availability (exams, internships) | Medium / High | Must/Should/Could scope, weekly exit criteria, cross-review pairs so each area has a second person who knows it |

## 2. Security risks (to the system itself)

| # | Threat | Where | Mitigation |
|---|---|---|---|
| S1 | **SSRF**: attacker submits `http://169.254.169.254/…` or a domain resolving to an internal IP | Redirect resolver, RDAP | Scheme and port allowlist, public-IP check on every resolved address, IP pinning, re-validation per hop, no bodies, timeouts (see `security.md`) |
| S2 | **DNS rebinding** (check passes, connection goes internal) | Redirect resolver | Connect to the already-validated IP |
| S3 | **Malicious image uploads** (decompression bombs, parser CVEs, polyglots) | Screenshot / QR image | Size and pixel caps, magic-byte check, `Image.verify()`, in-memory only, keep Pillow/OpenCV patched |
| S4 | **ReDoS** via crafted message text | Scam rules | No nested quantifiers, 5000-char cap, timing tests |
| S5 | **API abuse / quota exhaustion** (drains VirusTotal/GSB quotas, burns CPU with OCR) | All analyze routes | Rate limits per IP/uid, stricter OCR limit, TI cache, request size limits |
| S6 | **Secret leakage** (keys in git, in mobile bundle, in logs) | Repo, clients, logs | Server-only secrets, `.gitignore`, gitleaks in CI, log redaction. Only public Firebase config in clients. |
| S7 | **Broken access control** on history (IDOR) | `/api/history` | uid taken from the verified token only, Firestore owner rules, tests for cross-user access |
| S8 | **Privacy leakage**: sensitive messages/screenshots stored or logged, URLs sent to third parties | Backend, TI | Not stored, not logged. Domain + hash only. Lookup-only TI, local feeds first, disclosure in the privacy notice. |
| S9 | **XSS** from rendering attacker-controlled text/URLs | Web result page | React escaping, URLs as text, CSP |
| S10 | **Unsafe link opening** from the app | Mobile | OpenLinkGuard, scheme blocklist, double confirmation for MALICIOUS |
| S11 | **Oracle abuse**: scammers test their links against QRGUARD to tune them | API | Accepted residual risk (true of any public checker). Rate limits reduce it. |
| S12 | **Dependency vulnerabilities** | All | Pinned versions, Dependabot, `pip-audit`, `npm audit` |
| S13 | **Verbose errors** exposing stack traces or paths | Backend | Global error handlers, `DEBUG=False`, generic messages |
| S14 | **Unauthenticated public API**: the mobile app's API URL is public by nature | Backend | Rate limiting. Firebase App Check is listed as future scope. |
