# QRGUARD: Intelligent QR & Digital Scam Detection System

QRGUARD is a final-year Computer Engineering project. It is a defensive security assistant that
analyses **QR codes, URLs, suspicious messages and screenshots**. For each input it returns an
explainable risk assessment (**SAFE / SUSPICIOUS / MALICIOUS**) with a score, the reasons, and a
recommended safe action.

> QRGUARD gives an automated security assessment, **not a guarantee**. It never opens suspicious
> links automatically.

## Project status

**Feature-complete and deployment-ready.** The Flask backend analyses links, messages, screenshots
(OCR) and QR codes, checks threat intelligence and returns an explainable score. The React web app and
the Expo mobile app use it for every check, with Firebase sign-in, a private privacy-minimised
history, reports, account/privacy controls and an admin view.

| Suite | Result |
|---|---|
| Backend (pytest, incl. Firestore emulator) | 815 tests, 96% coverage, Ruff clean |
| Firestore security rules | 7 tests |
| Postman / Newman | 83 requests, 303 assertions |
| Web (Vitest) | 71 tests, 91% statements |
| Mobile (Jest) | 65 tests, 88% statements |
| End-to-end (`e2e/run.sh`: browsers → apps → Firebase emulators → Flask) | 16 flows + log privacy check |

See [docs/testing.md](docs/testing.md), [docs/evaluation.md](docs/evaluation.md) and
[docs/deployment.md](docs/deployment.md).

### Risk levels and verification

| Level | Meaning |
|---|---|
| ✅ **SAFE** (0–29) | No significant suspicious indicators detected. **Not a guarantee.** |
| ⚠️ **SUSPICIOUS** (30–59) | Several warning signs |
| ⛔ **MALICIOUS** (60–100) | Strong or decisive evidence of harm |

Each result also has a separate `verification` field. It is **VERIFIED** only when a trusted
source supports it (the curated trusted-domain list, or a threat-intelligence listing), and
**UNVERIFIED** otherwise. SAFE + UNVERIFIED is a normal result and is shown as "not guaranteed
safe". Verification never changes the score. "Not found in a threat database" never counts as
verification.

| Phase | Scope | Status |
|---|---|---|
| 1 | Architecture, folder structure, DB design, API design, roadmap | ✅ Approved |
| 2 | Backend foundation | ✅ Done |
| 3 | URL analysis, SSRF-safe redirect checking, risk-scoring engine | ✅ Done |
| 4 | Scam message detector | ✅ Done |
| 5 | Screenshot analysis (OCR) | ✅ Done |
| 6 | QR code analysis and generation | ✅ Done |
| 7 | Threat intelligence | ✅ Done |
| 8 | React web application | ✅ Done |
| 9 | React Native (Expo) mobile application | ✅ Done |
| 10 | Firebase sign-in, private history, reports, admin (backend, web, mobile) | ✅ Done |
| 11 | End-to-end tests, security audit, evaluation | ✅ Done |
| 12 | Deployment (Docker/Render, Vercel, EAS, Firebase) | ✅ Ready; needs account owners to deploy ([docs/deployment.md](docs/deployment.md)) |

"Done" means implemented, tested and in an open pull request; see each PR for review status.

## Design documents

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Final architecture, key decisions, tech stack, mobile, web and deployment architecture, data flows |
| [docs/folder-structure.md](docs/folder-structure.md) | Complete monorepo layout with per-member ownership |
| [docs/database-design.md](docs/database-design.md) | Firestore schema, privacy rules, security rules, ER diagram |
| [docs/api-spec.md](docs/api-spec.md) | REST API contract (v1) |
| [docs/risk-scoring.md](docs/risk-scoring.md) | Indicator catalogue, weights, combination model, thresholds, confidence |
| [docs/threat-intelligence.md](docs/threat-intelligence.md) | `ThreatIntelService` design and providers |
| [docs/security.md](docs/security.md) | Security controls including SSRF protection, and the security audit |
| [docs/testing.md](docs/testing.md) | Unit, integration, emulator, Newman and end-to-end tests |
| [docs/evaluation.md](docs/evaluation.md) | Measured precision/recall on held-out data, and error analysis |
| [docs/deployment.md](docs/deployment.md) | Firebase, Render, Vercel and EAS deployment, smoke test, go-live checklist |
| [docs/demo-runbook.md](docs/demo-runbook.md) | Final Android + web demonstration script, demo QR sheet, fallbacks |
| [docs/git-workflow.md](docs/git-workflow.md) | Branching, PRs, reviews, CI for a 4-member team |
| [docs/roadmap.md](docs/roadmap.md) | 12-week plan by member |
| [docs/risks.md](docs/risks.md) | Technical and security risks |
| [docs/research.md](docs/research.md) | Reference paper analysis (QsecR), research gap, contribution |
| [docs/demo-and-scope.md](docs/demo-and-scope.md) | Final demo script and out-of-scope items |

## Planned tech stack

Flask + Gunicorn (Docker, Render) · Tesseract OCR · OpenCV · React + Vite + TypeScript (Vercel) ·
React Native + Expo (EAS Build) · Firebase Auth + Cloud Firestore · URLhaus / Google Safe Browsing /
VirusTotal (optional, via env keys).

## Team

| Member | Area |
|---|---|
| Member 1 | Mobile application |
| Member 2 | Security / backend |
| Member 3 | AI / OCR / scam analysis |
| Member 4 | Web / DevOps / database |
