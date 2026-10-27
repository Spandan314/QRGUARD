# Changelog

## Redirect checker hardening (October 2026, `feature/redirect-hardening`)

- **Hard time limit per redirect request.** A socket read timeout restarts on every byte, so a
  hostile server dripping one header byte at a time could hold a request thread indefinitely. A
  watchdog now shuts the socket down at the request's wall-clock deadline (never beyond the total
  budget), and a response cut short this way is treated as a timeout, never as an answer. The
  GET fallback gets only what is left of the budget.
- **DNS lookups cannot starve each other.** Lookups ran on a shared pool of 4 threads and a
  timed-out `getaddrinfo` kept its thread, so four stuck lookups delayed every other one. Each
  lookup now has its own thread; at most 16 may be in flight (abandoned ones included), beyond
  which lookups fail at once.
- **Per-worker cap on concurrent redirect checks** (`REDIRECT_MAX_CONCURRENT`, default 2). When
  every slot is busy, the check is skipped and reported as incomplete (`capacity_exhausted`),
  never as clean.
- **`render.yaml` is back to `REDIRECT_RESOLUTION=shorteners_only`.** `all` is not enabled: it
  lets anyone make the backend contact a server of their choice for every analysed link.

## Link action, evidence and threat intelligence (October 2026, `feature/link-verdict-ti`)

- **Web: "Open checked link".** The web app never had an open action (links were plain text by
  design). It now has one: it opens only the exact analysed URL in a new tab without an opener,
  never automatically, after a confirmation that names the host (and any redirect), with a caution
  for unverified links and a ticked acknowledgement for malicious ones. `user@host` and non-web links
  are never opened. The link policy is shared with the Android app.
- **The demo blocklist is not threat intelligence.** A hit only on QRGUARD's synthetic demo list is
  `TI_DEMO_LISTED`: still MALICIOUS (floor 90), but UNVERIFIED, `verdict.confirmed: false`,
  `verdict.evidence: "demo_blocklist"`, and no HIGH confidence from that floor alone.
- **Evidence:** `verdict.evidence` (`threat_intelligence`, `trusted_list`, `warning_signs`,
  `demo_blocklist`, `insufficient`). A provider that times out, is rate limited or rejects its key
  makes the check `incomplete` / `unavailable`, named with the reason, and lowers confidence: never
  a clean result.
- **Providers:** timeouts reported as "timeout"; HTTP 509 (PhishTank) as "rate limited"; Safe
  Browsing's 400 invalid-key answer and URLhaus `unknown_auth_key` as configuration errors;
  optional `PHISHTANK_ANONYMOUS`; tests with complete documented response bodies; and
  `scripts/ti_selftest.py`, which proves a key works (Safe Browsing must list Google's official test
  page) without printing it. No provider is live-verified yet: no keys are configured.

## Mobile production hardening (October 2026, `feature/mobile-production-hardening`)

Details and root causes: docs/mobile-audit-2026-10.md.

### Changed

- **Evidence-based verdicts.** Every analysis response has a `verdict` (`MALICIOUS`,
  `SUSPICIOUS`, `UNVERIFIED`, `SAFE`). SAFE is reserved for positively recognised domains; an
  unknown site with no warning signs is shown as **NOT VERIFIED**, never SAFE. Android and web show
  the verdict as the headline. URL results list the `checks` behind the verdict (structure,
  destination/redirects, threat intelligence: completed, limited, not run or unavailable).
- **Exact links.** A bare word such as `offer` is rejected (`400 INCOMPLETE_URL`), never guessed.
  Unknown domain endings are explained (`URL_UNKNOWN_TLD`, 0 points). Passwords in links are
  masked in `analysis.input_url` too. The app opens only the exact checked URL, names its host and
  any redirect target before opening, cautions on unverified links, and never opens `user@host`
  links.
- **Redirects:** `render.yaml` briefly used `REDIRECT_RESOLUTION=all`; this was reverted to
  `shorteners_only` after a security review (see "Redirect checker hardening" above).
- **Android camera:** full permission flow (explain → request → denied → permanently denied with
  Open settings → re-check on return), camera start-up error recovery, and alternatives.
- **Android images:** "Check a screenshot" and "QR code from a photo" merged into **Choose image to
  check**. Images are resized/re-encoded on the phone (≤ 2000 px, JPEG, metadata removed). Uploads
  are diagnosed precisely (interrupted upload vs. server unreachable vs. server starting), with
  Try again. The server still analyses a QR code in an image when OCR fails or is unavailable.
  Storage permissions merged in by libraries are blocked. **Requires a new APK.**
- **Message rules:** four narrow additions found by a new labelled audit set (OTP "code sent to
  your phone", prize "claim your free … / shipping fee", new-number / in-a-meeting impersonation
  + money request, account threat or KYC demand + link). The fake-KYC demo now scores 75 instead
  of 65 (still MALICIOUS). Measured before/after in docs/evaluation.md.

## Free-plan deployment fixes (after v1.0.0, on `main`)

### Changed

- **Runs on the free Firebase Spark plan.** The Firestore TTL policy on `scans.expire_at` is removed
  (TTL needs billing). The 90-day retention is now enforced by the backend: expired results are
  never returned or reportable, a user's expired results are deleted when they sign in or open
  their history, and an admin can delete every user's expired results with the new
  `POST /api/admin/history/purge-expired` endpoint, the "Delete expired history now" button on the
  web Admin page or `flask --app wsgi purge-expired-history`. There is no scheduled job, so expired
  results of a user who never returns stay stored (hidden) until an admin purge.
- **No Firestore field overrides.** The `scans.expire_at` field override is removed as well
  (`"fieldOverrides": []`): on Spark any field override fails to deploy with "billing disabled".
  The admin purge now queries each user's `scans` (automatic single-field index) instead of a
  collection-group query.

## v1.0.0 — final submission release

The complete QRGUARD system: an explainable scam and QR-code checker with a Flask API, a React web
app and an Expo (Android) app, backed by Firebase for sign-in and a privacy-minimised history.

### Analysis (backend)

- **Links** — URL normalisation, look-alike/typosquat and brand checks, risky TLDs, IP hosts,
  punycode, user-info tricks, executable downloads; SSRF-safe redirect checking (shorteners only by
  default; private, loopback and cloud-metadata addresses are never contacted). (baseline)
- **Messages** — rule-based scam detector for fake KYC, OTP requests, job/fee, prize, refund and
  UPI scams, with genuine-advice detection and per-source score breakdown. (baseline)
- **Screenshots** — Tesseract OCR in memory; text goes through the message pipeline; QR codes
  inside screenshots are decoded too. Images and extracted text are never stored. (#2)
- **QR codes** — OpenCV decoding (camera content or image), UPI / Wi-Fi / SMS / vCard / link
  payloads, "scan to receive money" detection, Wi-Fi passwords never returned; QR generator. (#3)
- **Threat intelligence** — local demo blocklist plus URLhaus, Google Safe Browsing, VirusTotal and
  PhishTank when keys are set; parallel, time-boxed and cached. A listing is decisive; "not listed"
  never lowers a score or counts as verification. (#4)
- **Scoring** — SAFE 0–29 / SUSPICIOUS 30–59 / MALICIOUS 60–100 with reasons, confidence,
  recommendation and a separate VERIFIED / UNVERIFIED status that never changes the score.

### Accounts, history and privacy

- Firebase sign-in (anonymous or e-mail) verified on the server; opt-in history that stores only the
  verdict and a minimised target (domain + URL hash, message length, UPI payee domain); delete one,
  delete all, delete my data; 90-day expiry; reports; admin statistics and
  report review behind a custom claim; `flask set-admin` command. (#7, #10)

### Web app (#5, #8)

- Link, message, screenshot and QR (upload or live camera) checks, QR generator, history,
  account/privacy controls, reports and admin dashboard. Security headers and CSP via `vercel.json`.

### Android app (#6, #9)

- Camera QR scanning, gallery QR, link/message/screenshot checks, open-link guard, QR generator,
  history, account/privacy controls and reports. EAS preview (APK) and production (AAB) profiles.

### Quality, deployment and demo (#10, #11, final audit)

- 800+ backend tests (96% coverage at v1.0.0), Firestore rules and emulator tests, Postman/Newman collection,
  web and mobile unit tests, and whole-system browser E2E tests under the production headers.
- Held-out evaluation with honest error analysis (`docs/evaluation.md`).
- Render Blueprint, Docker image, Vercel and EAS configuration with build-time guards against
  unsafe settings; post-deployment smoke test; demo kit and runbook.
- Final audit: exception messages are no longer written to logs (only exception types and stack
  frames), so user input echoed by a library error cannot reach the logs; documentation brought up
  to date; version 1.0.0.

See `docs/deployment.md` for deployment and `docs/demo-runbook.md` for the demonstration.
