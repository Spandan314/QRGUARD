# Mobile production-readiness audit (October 2026)

This audit followed the first real-device tests of the Android preview build, which uses the
Render backend and the Firebase Spark plan. It records the defects that were reported, their root
causes, what changed, and what QRGUARD does and does not do, checked against the intended
architecture diagram. Branch: `feature/mobile-production-hardening`.

## 1. Reported defects and root causes

| # | Reported | Root cause (verified in code / by measurement) | Fix |
|---|---|---|---|
| 1 | `offer.com` was shown as **SAFE** while the screen said no threat-intelligence provider was enabled | The apps showed the **score band** (`risk_level`) as the headline. A domain with no warning signs scores 0, which is the SAFE band. The separate `verification` field (UNVERIFIED) appeared only in small print. Bare words such as `offer` and unknown endings such as `offer.c` were also accepted and scored. | A new headline **`verdict`**: SAFE only for a positively recognised domain, otherwise **UNVERIFIED** ("Not verified – no known risks found"). A `checks` list shows what ran and what could not. Bare words are rejected (`INCOMPLETE_URL`). Unknown endings get an explanatory `URL_UNKNOWN_TLD` indicator. §3. |
| 2 | Tapping **Open link** for `offer.com` opened `offers.com` | The app opened exactly `https://offer.com/`. `OpenLinkGuard` passes the normalized URL to `Linking.openURL` unchanged, and the tests prove it. The switch happens after the browser loads the page, which points to an HTTP redirect by the website. The backend followed redirects only for known URL shorteners (`REDIRECT_RESOLUTION=shorteners_only`), so it never saw this one. This explanation is consistent with the code, but this sandbox cannot reach `offer.com` to confirm the redirect. | Not changed in production: following every link (`REDIRECT_RESOLUTION=all`) was reviewed and rejected because it lets anyone make the backend contact a server of their choice (`docs/security.md`). `render.yaml` keeps `shorteners_only`; such a site redirect is therefore not reported. The open-link dialog still names the exact host being opened. |
| 3 | A genuine Google Pay screenshot failed with "Cannot reach the QRGUARD server" | That message meant `fetch` threw, i.e. the connection failed. It is not an HTTP error. The backend pipeline is light: a 1080×2400 screenshot took about 1 CPU-second, and production Gunicorn with Firebase loaded peaked at about 341 MB, measured. The client, however, uploaded full-resolution originals with no resizing. Over 5 MB, the server rejects the upload mid-transfer, which Android reports as a network failure. Every connection failure was also reported as "check your internet", and there was no retry. Render's logs for the failed request were not available to this audit, so its exact cause cannot be proven from here. | Images are re-encoded on the phone (longest side ≤ 2000 px, JPEG, metadata such as GPS removed). Uploads get a 90 s timeout. A failed upload is diagnosed by probing `/api/health` (`UPLOAD_FAILED` = server reachable, upload interrupted; `NETWORK_ERROR` = unreachable). Platform 5xx pages give `SERVER_UNAVAILABLE`, and 413 gives `PAYLOAD_TOO_LARGE`. Every error has a specific hint and a **Try again** button. |
| 4 | Camera permission prompt without recovery | The screen had one "Allow camera" button. A permanently denied permission could not be recovered from the app, and the state was not re-read after returning from Settings. | Explanation → request; after a denial, explanation plus request again; after a permanent denial, **Open settings** plus **I allowed it – check again**. The permission is re-read on app focus. Camera start-up errors offer retry, and alternatives are offered (choose an image, type the link). |
| 5 | "Check a screenshot" and "QR code from photo" were confusing duplicates | Both opened the gallery. The screenshot endpoint already decoded QR codes *and* ran OCR, so it was a superset, except that an OCR failure aborted the check even when a QR code was present. | One **Choose image to check** flow using `/api/analyze/screenshot`. A QR code alone is analysed like a scanned code, text like a message, and both are analysed when both exist. If OCR fails or is unavailable, a QR code in the image is still analysed. |

Privacy issue found during the audit: a password typed into a link (`user:secret@host`) was masked
in `normalized_url` but echoed in `analysis.input_url`. It is now masked there too (regression
test `test_passwords_in_links_are_never_echoed`).

## 2. Architecture diagram vs implementation

Status: **Implemented** (code + tests), **Partial**, **External** (works only with a provider key),
**Not implemented** (deliberately; see the reason).

| Stage (diagram) | Source | Status | Inputs → outputs | Tests | External dependency |
|---|---|---|---|---|---|
| 1. Input: scan / upload | `mobile/src/app/scan/camera.tsx` (expo-camera), `mobile/src/app/check/image.tsx` + `components/ImagePickerField.tsx` + `services/imagePrep.ts`, `check/url.tsx`, `check/message.tsx` | Implemented | camera frames / gallery image / typed text → decoded QR text, prepared JPEG, URL, message | `mobile/src/test/screens.test.tsx` | Camera permission only |
| 2. QR decoding | On the phone: expo-camera barcode scanner. On the server: `app/analyzers/qr_decoder.decode_qr_codes` (OpenCV), `qr_payload.classify` | Implemented | image / frames → payload(s) classified as url, upi, wifi, tel, text … | `tests/unit/test_qr_decoder.py`, `test_qr_payload.py`, `tests/integration/test_api_qr.py`, `test_verdict_policy.py` (QR when OCR fails) | – |
| 3. Pre-processing | `app/analyzers/url_normalizer.normalize_url` (validation, IDN/punycode, percent-decoding of the host, user-info masking, no spelling correction), `redirect_resolver.resolve_redirects` | Implemented | raw text → `ParsedURL` or `400 INVALID_URL / INCOMPLETE_URL / UNSUPPORTED_PROTOCOL` | `tests/unit/test_url_normalizer.py`, `test_redirect_resolver.py`, `test_verdict_policy.py` | Redirects: outbound HTTP(S) to the link's host (`REDIRECT_RESOLUTION`) |
| 4. Backend API | `app/routes/analyze.py` (`/api/analyze/url`, `/message`, `/screenshot`, `/qr`), validation, rate limits, auth | Implemented | HTTPS JSON / multipart → analysis JSON incl. `verdict`, `checks` | `tests/integration/test_api_*.py`, Postman/Newman | Render |
| 5a. Lexical analysis | `app/analyzers/url_features.extract_url_features` (length, special characters, IP host, encoding, user-info, subdomain depth, executable downloads, risky TLDs, unknown TLD) | Implemented | `ParsedURL` → indicators | `tests/unit/test_url_features.py` | – |
| 5b. Domain & reputation | `lookalike.detect_lookalikes` (typosquatting, brand in subdomain/domain, homoglyphs), trusted-domain list | Partial | `ParsedURL` → indicators | `tests/unit/test_lookalike.py` | **WHOIS / domain age: not implemented.** No free, keyless, reliable WHOIS/RDAP source fits the free plan, and it is not faked. |
| 5c. Content & behaviour | Redirect chain, cross-domain destination, HTTPS downgrade, DNS failure, TLS errors (from `redirect_resolver`) | Partial | URL → redirect indicators + `checks.destination` | `test_redirect_resolver.py`, `test_verdict_policy.py` | Outbound requests. **Page content (hidden forms, iframes, keywords on the page) is not downloaded or analysed.** That would make the server fetch attacker-controlled content; it is out of scope for safety. |
| 5d. Blacklists & databases | `app/threat_intelligence/` (`local_feed`, `urlhaus`, `safe_browsing`, `virustotal`, `phishtank`): timeouts, 429 → unavailable, 401/403 → error, caching, time budget | Implemented (demo list); **External** for the four providers | URL → provider statuses → `TI_LISTED` / `TI_PARTIAL` | `tests/unit/test_threat_intel_providers.py`, `test_threat_intel_service.py`, `tests/integration/test_api_threat_intel.py` (all with fakes) | API keys on Render (deployment.md §2a). Without keys only the small demo blocklist runs, and results say so. |
| 5e. (Optional) ML engine | – | **Not implemented** | – | – | No model is trained, loaded or used, and none is claimed. Scoring is rule-based and explainable. |
| 6. Risk scoring & classification | `app/scoring/engine.score_indicators` (score 0–100, band, confidence, verification), `scoring/recommendations.verdict_for` (headline verdict) | Implemented | indicators → score, `risk_level`, `verification`, `verdict` | `tests/unit/test_scoring_engine.py`, `test_verdict_policy.py`, `test_audit_messages.py` | – |
| 7. Final result | `mobile/src/components/ResultView.tsx`, `OpenLinkGuard.tsx`; `web/src/components/ResultCard.tsx` | Implemented | analysis JSON → verdict badge, title, score, reasons, checks, redirect target, recommendation, guarded link opening | `ResultView.test.tsx`, `links.test.ts`, web `ResultCard.test.tsx` | – |
| Message analysis | `app/analyzers/message_analyzer.py`, `scam_rules.py`, `data/scam_rules.yaml` | Implemented (rule-based) | text → indicators + extracted links (each analysed as in stage 3–5) | `test_api_message.py`, `test_demo_messages.py`, `test_audit_messages.py`, `scripts/evaluate.py` | – |
| Screenshot OCR | `app/analyzers/ocr.py` (Tesseract), `services/screenshot_analysis_service.py` | Implemented | image → text (+ QR) → message pipeline | `test_api_screenshot.py` (incl. real Tesseract), `test_verdict_policy.py` | Tesseract in the Docker image |

## 3. Verdict policy (evidence-based)

| Headline (`verdict.label`) | When | Shown as |
|---|---|---|
| `MALICIOUS` (`confirmed: true`) | a threat-intelligence source lists the URL | ⛔ MALICIOUS – listed by threat intelligence |
| `MALICIOUS` | score ≥ 60 from QRGUARD's own rules | ⛔ MALICIOUS – Very likely malicious |
| `SUSPICIOUS` | score 30–59 | ⚠️ SUSPICIOUS |
| `SAFE` | score < 30 **and** the domain is on the curated trusted list with no medium-or-worse sign | ✅ SAFE – Recognised legitimate website |
| `UNVERIFIED` | everything else with score < 30: no warning signs, but no evidence of safety | ❔ NOT VERIFIED – no known risks found |

- "Not listed" by any provider, real or demo, is never evidence of safety. A message never gets
  `SAFE`: no source can verify that a message is genuine.
- Unfamiliar, unreachable or non-resolving domains are **not** called malicious for that alone.
  A non-resolving domain is reported as a `DOMAIN_NOT_RESOLVING` indicator and an incomplete
  check.
- Malformed input never reaches a verdict: it gets a 400 with a correction hint, and the app never
  "corrects" a domain.
- `risk_level` (the score band) is unchanged for API compatibility, history and the evaluation.
  Clients show `verdict`, and derive it the same way for older responses and history items
  (`utils/verdict.ts`).

## 4. Message detection: measured, not assumed

A new labelled set, `demo-data/evaluation/audit-2026-10.yaml` (16 scams across the requested
families, 16 genuine messages that use words like OTP, bank, urgent, refund and KYC), was measured
**before** any rule change:

| Measurement | Recall | Precision | False positives | Genuine → MALICIOUS |
|---|---|---|---|---|
| Audit set, before rule changes (honest) | 0.688 (11/16) | 1.000 | 0 / 16 | 0 |
| Audit set, after rule changes (**in-sample**) | 1.000 | 1.000 | 0 / 16 | 0 |
| Original hold-out, unchanged (never tuned on) | 0.833 | 0.909 | 1 / 12 | 0 |

The five misses led to four narrow rule additions:
- "share the code sent to your phone" as an OTP request;
- "lucky customer / claim your free …" and "only pay shipping fee";
- a new-number / in-a-meeting / keep-it-confidential impersonation pretext, combined with a money
  request;
- an account threat or KYC demand combined with a link.

The hold-out set still misses `m-crypto-doubling` and `m-gift-card-boss` (the latter now scores
25, still below the threshold). Those are documented, not hidden.

## 5. Limitations that remain

- **Threat intelligence needs keys.** Without them, link verdicts rest on structure, look-alike
  detection and redirects only, and results say so (`checks.threat_intelligence: limited`).
- **Ordinary links' redirects are not followed.** `REDIRECT_RESOLUTION` stays `shorteners_only`
  (a security review rejected `all`, see `docs/security.md`), so a site's own redirect
  (offer.com → offers.com) is not shown.
- **No WHOIS/domain age, no page-content analysis, no ML.** These are deliberate; see §2.
- **No Android native build was run in the audit environment** (EAS needs the owner's Expo
  account). The JavaScript bundle for Android compiles (`npx expo export --platform android`) and
  all unit/component tests pass. Camera permission flows were tested with mocked permission
  states and still need a check on a real phone.
- A new APK is required: `expo-image-manipulator` is a new native module, and the permission
  changes only apply to a new build.
- The Render instance is the free tier: cold starts take 30–60 s, and an image check can take
  tens of seconds on its shared CPU.
