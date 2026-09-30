# Changelog

## Unreleased

### Changed

- **Runs on the free Firebase Spark plan.** The Firestore TTL policy on `scans.expire_at` is removed
  (TTL needs billing). The 90-day retention is now enforced by the backend: expired results are
  never returned or reportable, a user's expired results are deleted when they sign in or open
  their history, and an admin can delete every user's expired results with the new
  `POST /api/admin/history/purge-expired` endpoint, the "Delete expired history now" button on the
  web Admin page or `flask --app wsgi purge-expired-history`. There is no scheduled job, so expired
  results of a user who never returns stay stored (hidden) until an admin purge.

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

- 800+ backend tests (96% coverage), Firestore rules and emulator tests, Postman/Newman collection,
  web and mobile unit tests, and whole-system browser E2E tests under the production headers.
- Held-out evaluation with honest error analysis (`docs/evaluation.md`).
- Render Blueprint, Docker image, Vercel and EAS configuration with build-time guards against
  unsafe settings; post-deployment smoke test; demo kit and runbook.
- Final audit: exception messages are no longer written to logs (only exception types and stack
  frames), so user input echoed by a library error cannot reach the logs; documentation brought up
  to date; version 1.0.0.

See `docs/deployment.md` for deployment and `docs/demo-runbook.md` for the demonstration.
