# QRGUARD: Intelligent QR & Digital Scam Detection System

QRGUARD is a final-year Computer Engineering project. It is a defensive security assistant that
analyses **QR codes, URLs, suspicious messages and screenshots**. For each input it returns an
explainable risk assessment (**SAFE / SUSPICIOUS / MALICIOUS**) with a score, the reasons, and a
recommended safe action.

> QRGUARD gives an automated security assessment, **not a guarantee**. It never opens suspicious
> links automatically.

## Project status

**Version 1.0.0 — feature-complete and deployment-ready.** The Flask backend analyses links, messages, screenshots
(OCR) and QR codes, checks threat intelligence and returns an explainable score. The React web app and
the Expo mobile app use it for every check, with Firebase sign-in, a private privacy-minimised
history, reports, account/privacy controls and an admin view.

| Suite | Result |
|---|---|
| Backend (pytest, incl. Firestore emulator) | 821 tests, 96% coverage, Ruff clean |
| Firestore security rules | 7 tests |
| Postman / Newman | 83 requests, 303 assertions |
| Web (Vitest) | 73 tests, 91% statements, lint with zero warnings |
| Mobile (Jest) | 65 tests, 88% statements, lint with zero warnings |
| End-to-end (`e2e/run.sh`: browsers → apps → Firebase emulators → Flask, production headers) | 18 flows + log privacy check |
| Demo kit / smoke test | 11/11 demo scenarios, 11/11 deployment checks |

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

"Done" means implemented, tested and merged into `develop` (PRs #2–#11).

## Run it locally

Requirements: Python 3.12 (3.11+ works), Node.js 22, Tesseract OCR (`apt install tesseract-ocr`,
`brew install tesseract`, or the UB-Mannheim installer on Windows) and, for the Firestore emulator
only, Java 21.

```bash
# 1. Backend  → http://localhost:5000/api/health
cd backend
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
AUTH_DEV_TOKENS=true HISTORY_STORE=memory flask --app wsgi run --port 5000   # demo accounts, no Firebase

# 2. Web app  → http://localhost:5173
cd web && npm ci
VITE_API_BASE_URL=http://localhost:5000 VITE_AUTH_MODE=dev npm run dev

# 3. Mobile app (Expo Go on a phone on the same Wi-Fi)
cd mobile && npm ci
EXPO_PUBLIC_API_BASE_URL=http://<your-LAN-IP>:5000 EXPO_PUBLIC_AUTH_MODE=dev npx expo start
```

`AUTH_DEV_TOKENS` / `VITE_AUTH_MODE=dev` give demo accounts without a Firebase project; the backend
refuses them in production. Each app's README has the details, [docs/testing.md](docs/testing.md)
lists every test command, and [docs/deployment.md](docs/deployment.md) covers production.

## Known limitations

QRGUARD is an explainable, rule-based assistant, not a guarantee. Known limitations are documented
next to each component:

- Messages: English rules only; novel wording can be missed ([risk-scoring §11.8](docs/risk-scoring.md)).
- Screenshots: OCR quality depends on the image ([risk-scoring §12.3](docs/risk-scoring.md)).
- QR codes: a UPI QR alone is at most SUSPICIOUS by design ([risk-scoring §13.5](docs/risk-scoring.md)).
- Threat intelligence: only the demo blocklist without API keys; "not listed" never means safe
  ([threat-intelligence §9](docs/threat-intelligence.md)).
- Measured errors on held-out data, including missed scams, are in [docs/evaluation.md](docs/evaluation.md).

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

## Tech stack

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
