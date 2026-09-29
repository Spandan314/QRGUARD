# QRGUARD: Intelligent QR & Digital Scam Detection System

QRGUARD is a final-year Computer Engineering project. It is a defensive security assistant that
analyses **QR codes, URLs, suspicious messages and screenshots**. For each input it returns an
explainable risk assessment (**SAFE / SUSPICIOUS / MALICIOUS**) with a score, the reasons, and a
recommended safe action.

> QRGUARD gives an automated security assessment, **not a guarantee**. It never opens suspicious
> links automatically.

## Project status

**URL analysis, risk-scoring engine, scam-message detector and screenshot OCR implemented.**
`POST /api/analyze/url`, `/message` and `/screenshot` are live and tested (515 automated tests,
Postman collection with 42 requests). Screenshot analysis needs Tesseract OCR installed. See
[backend/README.md](backend/README.md) and [docs/testing.md](docs/testing.md).

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
| 3a | URL analysis, SSRF-safe redirect checking, risk-scoring engine | ✅ Done (awaiting review) |
| 3b | Scam message detector | ✅ Done (awaiting review) |
| 3c | OCR / screenshot analyzer | ✅ Done (PR open) |
| 4 | Threat intelligence | ⏳ |
| 5 | React web application | ⏳ |
| 6 | React Native (Expo) mobile application | ⏳ |
| 7 | Firebase integration | ⏳ |
| 8 | Testing | ⏳ |
| 9 | Deployment | ⏳ |
| 10 | Final documentation | ⏳ |

## Design documents

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Final architecture, key decisions, tech stack, mobile, web and deployment architecture, data flows |
| [docs/folder-structure.md](docs/folder-structure.md) | Complete monorepo layout with per-member ownership |
| [docs/database-design.md](docs/database-design.md) | Firestore schema, privacy rules, security rules, ER diagram |
| [docs/api-spec.md](docs/api-spec.md) | REST API contract (v1) |
| [docs/risk-scoring.md](docs/risk-scoring.md) | Indicator catalogue, weights, combination model, thresholds, confidence |
| [docs/threat-intelligence.md](docs/threat-intelligence.md) | `ThreatIntelService` design and providers |
| [docs/security.md](docs/security.md) | Security controls including SSRF protection |
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
