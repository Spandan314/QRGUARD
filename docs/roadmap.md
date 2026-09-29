# 12-Week Development Roadmap

## Changes from the proposed schedule (and why)

The proposed schedule works through one topic per week in sequence. With **four people**, a strict
sequence leaves three members idle each week. We keep the same topics and order of *backend*
capability, but:

1. **Run the four streams in parallel from Week 2**, using the frozen API contract and mock responses.
2. **Deploy in Week 2, not Week 12.** A "hello world" backend Docker image with Tesseract on Render
   surfaces deployment problems (memory, build time, system packages) when they are still cheap to fix.
3. **Build the scoring engine skeleton in Week 3**, because every analyzer depends on the `Indicator`
   contract. Week 8 becomes *calibration* of the scoring engine rather than first creation.
4. **Start the evaluation dataset early** (Week 3 onward, M3). Otherwise there is nothing honest to
   report in "Results".

## Weekly plan

| Wk | Theme | M1 Mobile | M2 Security/Backend | M3 Scam/OCR | M4 Web/DevOps/DB | Exit criterion |
|---|---|---|---|---|---|---|
| 1 | Architecture, GitHub, UI design | Figma wireframes for 11 screens, Expo hello-world on phones | Review API spec, Flask skeleton plan | Read QsecR full text + 5 papers, draft scam taxonomy | Repo, branch protection, board, CODEOWNERS, CI stubs, Firebase project | Architecture approved; everyone can run their app locally |
| 2 | Backend foundation + Firebase | Navigation shell (expo-router, tabs), theme, mock API service | App factory, config, errors, `/api/health`, validation, rate limits, CORS, logging, **Dockerfile + Render deploy** | Tesseract installed locally, OCR spike on 10 sample screenshots | Firebase Auth (anonymous), Admin SDK service, Firestore rules v1 + emulator, web Vite shell | Deployed `/api/health` returns `ok` with `ocr: ok` |
| 3 | QR scanner + decoder | Camera scanner, gallery picker, result screen v1 (mock) | `qr_decoder.py`, `qr_payload.py` (URL/UPI/Wi-Fi/tel/email), `/api/analyze/qr`, **Indicator + scoring skeleton** | `text_utils.py` normalisation, start `demo-data/messages.yaml` (≥ 40 items) | Web layout, RiskBadge/IndicatorList components, QR image page (mock) | Scanning a QR on the phone returns the decoded type from the real API |
| 4 | URL analysis | URL checker screen, OpenLinkGuard | `url_normalizer`, `url_features`, `lookalike`, data lists, unit tests | `url_extractor.py` (de-obfuscation) + tests | URL checker page wired to the real API, history service (write) | **v0.1-alpha:** URL → explained score on web and mobile |
| 5 | Scam message detector | Message checker screen | Safe redirect resolver + SSRF tests | `scam_rules.yaml`, `message_analyzer.py`, negation handling, combo bonuses, tests | Message page, `GET/DELETE /api/history`, history page | Genuine bank SMS → SAFE; fake KYC SMS → SUSPICIOUS+ |
| 6 | OCR / screenshot | Screenshot screen, upload progress | Upload validation hardening (magic bytes, pixel cap) | `ocr.py` preprocessing, confidence, `screenshot_analyzer.py` (+QR in screenshot) | Screenshot page, drag-and-drop | Screenshot of a demo scam → text, URLs, phrases, score |
| 7 | Threat intelligence | TI status component | `ThreatIntelService`, local feeds, URLhaus, GSB, VT, cache, budget, domain age (RDAP) | Recommendation texts per category | Health page shows provider status, admin stats endpoint | Provider down → result still returned with "unavailable" |
| 8 | Risk scoring calibration | History screen, swipe delete | Tune weights on the evaluation set, confidence rules | Evaluation script: precision/recall/confusion matrix per input type | Admin dashboard (stats + reports) | **v0.2-beta:** metrics table produced from real runs |
| 9 | Mobile integration | QR generator (save/share), settings, auth, real API everywhere, error states, EAS preview APK | Bug fixes from mobile integration, perf (OCR time) | Fix false positives found by M1 testing | Postman collection + Newman in CI | APK installed on 3 physical phones and working against the deployed backend |
| 10 | Web platform completion | UI polish, accessibility pass | Security headers, `pip-audit`, secrets scan | Hindi/Marathi feasibility note (future scope only) | QR generator, About, Security tips, responsive pass, Vercel deploy | Web deployed on Vercel against the production API |
| 11 | Testing + security | Device testing matrix, UX test with 5 non-technical users | Security test suite (SSRF, uploads, malformed, rate limit, auth) | Integration tests for message/screenshot flows | Firestore rules tests (emulator), E2E demo script | **v1.0-rc:** all CI green, test report written |
| 12 | Deployment, docs, presentation | Production AAB/APK, screenshots | API docs final | Results chapter (metrics) | README, deployment guide, report compile, slides | **v1.0** tagged, report + demo rehearsed twice |

## Buffer

Week 11 is intentionally shared between testing and fixes. If a stream slips, cut from
**"Could have"** first:

- **Must:** URL / message / QR (camera + image) / screenshot analysis, scoring with reasons, mobile + web, history + delete, deployment.
- **Should:** URLhaus + GSB, redirect resolution, admin stats, QR generator save/share.
- **Could:** VirusTotal, domain age, reports workflow, dark/light toggle, email/password upgrade.
