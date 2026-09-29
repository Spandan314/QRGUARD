# Complete Folder Structure

Owner codes: **M1** Mobile · **M2** Security/Backend · **M3** AI/OCR/Scam analysis · **M4** Web/DevOps/DB.
Each top-level folder has one primary owner, which keeps merge conflicts rare.

```
QRGUARD/
├── README.md                              M4
├── .gitignore                             M4
├── .env.example                           M4  (index of all variables; each app also has its own)
├── .github/
│   ├── CODEOWNERS                         M4
│   ├── PULL_REQUEST_TEMPLATE.md           M4
│   ├── ISSUE_TEMPLATE/{bug,feature}.md    M4
│   ├── dependabot.yml                     M4
│   └── workflows/
│       ├── backend-ci.yml                 M2  (ruff + pytest, runs only on backend/**)
│       ├── web-ci.yml                     M4  (lint + typecheck + build, web/**)
│       └── mobile-ci.yml                  M1  (lint + tsc, mobile/**)
│
├── backend/
│   ├── app/
│   │   ├── __init__.py                    M2  create_app() factory
│   │   ├── config.py                      M2  env → Config object (thresholds, limits, flags)
│   │   ├── extensions.py                  M2  limiter, cors, firebase init
│   │   ├── errors.py                      M2  APIError + JSON error handlers (no stack traces)
│   │   ├── schemas.py                     M2  Pydantic request models
│   │   ├── routes/
│   │   │   ├── health.py                  M2  GET /api/health
│   │   │   ├── analyze.py                 M2  POST /api/analyze/{url,message,screenshot,qr}
│   │   │   ├── generate.py                M2  POST /api/generate/qr
│   │   │   ├── history.py                 M4  GET/DELETE /api/history
│   │   │   ├── reports.py                 M4  POST /api/reports
│   │   │   └── admin.py                   M4  GET /api/admin/stats, /api/admin/reports
│   │   ├── services/
│   │   │   ├── analysis_service.py        M2  orchestrator: input → modules → TI → scoring
│   │   │   ├── auth.py                    M4  @optional_auth / @require_auth / @require_admin
│   │   │   ├── firebase_service.py        M4  Admin SDK wrapper (disabled mode if not configured)
│   │   │   └── history_service.py         M4  privacy-minimised writes, pagination, deletes
│   │   ├── analyzers/
│   │   │   ├── url_normalizer.py          M2  scheme fix, IDNA, lowercase host, strip fragments
│   │   │   ├── url_features.py            M2  structural + lexical indicators
│   │   │   ├── lookalike.py               M2  brand typosquat / homoglyph detection
│   │   │   ├── redirect_resolver.py       M2  SSRF-guarded HEAD-only redirect following
│   │   │   ├── domain_age.py              M2  RDAP lookup (best-effort)
│   │   │   ├── qr_decoder.py              M2  OpenCV decode from image bytes
│   │   │   ├── qr_payload.py              M2  classify + parse URL/UPI/WIFI/tel/mailto/text
│   │   │   ├── message_analyzer.py        M3  feature extraction + rule evaluation
│   │   │   ├── message_rules.py           M3  loads data/scam_rules.yaml, compiles patterns
│   │   │   ├── url_extractor.py           M3  URLs from free text incl. de-obfuscation
│   │   │   ├── ocr.py                     M3  preprocessing + Tesseract + confidence
│   │   │   └── screenshot_analyzer.py     M3  OCR → message + URL + QR → combined
│   │   ├── threat_intelligence/
│   │   │   ├── base.py                    M2  ThreatIntelProvider ABC, ProviderResult
│   │   │   ├── service.py                 M2  ThreatIntelService (parallel, cache, budget)
│   │   │   ├── cache.py                   M2
│   │   │   └── providers/
│   │   │       ├── local_feed.py          M2  OpenPhish/URLhaus dumps + demo blocklist
│   │   │       ├── urlhaus.py             M2
│   │   │       ├── safe_browsing.py       M2
│   │   │       ├── virustotal.py          M2  lookup only, never submit
│   │   │       └── phishtank.py           M2  optional
│   │   ├── scoring/
│   │   │   ├── indicator.py               M2  Indicator dataclass (shared contract!)
│   │   │   ├── engine.py                  M2  combine, cap, floor, level, confidence
│   │   │   ├── recommendations.py         M3  action text per level + dominant category
│   │   │   └── weights.yaml               M2+M3  all weights, caps, thresholds
│   │   ├── utils/
│   │   │   ├── net_safety.py              M2  is_public_ip(), safe resolve, port allowlist
│   │   │   ├── image_utils.py             M3  magic-byte check, Pillow verify, pixel cap
│   │   │   ├── text_utils.py              M3  NFKC, leetspeak/homoglyph normalisation
│   │   │   ├── hashing.py                 M4  sha256 for URL hashes
│   │   │   └── logging_setup.py           M2  JSON logs, request_id, redaction
│   │   └── data/
│   │       ├── brands.json                M2  brand → official domains
│   │       ├── trusted_domains.txt        M2
│   │       ├── suspicious_tlds.txt        M2
│   │       ├── url_shorteners.txt         M2
│   │       ├── phishing_keywords.txt      M2
│   │       ├── scam_rules.yaml            M3  categories, patterns, negations, combos
│   │       └── demo_blocklist.txt         M2  DEMO/TEST entries (.test/.example TLDs only)
│   ├── tests/
│   │   ├── conftest.py
│   │   ├── unit/                          test_url_normalizer.py, test_url_features.py, test_lookalike.py,
│   │   │                                  test_qr_payload.py, test_message_analyzer.py, test_ocr.py,
│   │   │                                  test_scoring_engine.py, test_net_safety.py, test_ti_service.py
│   │   ├── integration/                   test_api_url.py, test_api_message.py, test_api_qr.py,
│   │   │                                  test_api_screenshot.py, test_api_history.py
│   │   ├── security/                      test_ssrf.py, test_uploads.py, test_rate_limit.py, test_malformed.py
│   │   └── fixtures/                      qr_*.png, screenshot_*.png, messages.yaml, urls.yaml
│   ├── wsgi.py
│   ├── gunicorn.conf.py
│   ├── Dockerfile                         (python:3.12-slim + tesseract-ocr)
│   ├── requirements.txt / requirements-dev.txt
│   ├── pyproject.toml                     (ruff + pytest config)
│   └── .env.example
│
├── web/                                   M4  (see architecture.md §4)
├── mobile/                                M1  (see architecture.md §3)
│
├── firebase/                              M4
│   ├── firebase.json
│   ├── firestore.rules
│   └── firestore.indexes.json
│
├── postman/                               M2+M4
│   ├── QRGUARD.postman_collection.json
│   └── QRGUARD.local.postman_environment.json
│
├── demo-data/                             M3  ALL files labelled DEMO / TEST DATA
│   ├── README.md
│   ├── messages.yaml                      genuine vs scam messages with expected level
│   ├── urls.yaml
│   ├── qr/                                generated QR PNGs (harmless payloads)
│   └── screenshots/                       synthetic screenshots (no real people's data)
│
└── docs/
    ├── architecture.md  folder-structure.md  database-design.md  api-spec.md
    ├── risk-scoring.md  threat-intelligence.md  security.md  git-workflow.md
    ├── roadmap.md  risks.md  research.md  demo-and-scope.md
    ├── deployment.md (Phase 9)  testing.md (Phase 8)  report/ (Phase 10)
    └── diagrams/  (Mermaid sources)
```

## Shared contracts (the only files that need cross-member review)

| File | Why it matters | Change rule |
|---|---|---|
| `docs/api-spec.md` | Web, mobile and backend all depend on it | PR needs approval from M1 **and** M4 |
| `backend/app/scoring/indicator.py` | M2 and M3 modules both emit it | PR needs approval from M2 **and** M3 |
| `backend/app/scoring/weights.yaml` | Tuning affects every result | Change only with updated tests |
| `web/src/types/api.ts`, `mobile/types/api.ts` | Mirror of the API schema | Updated in the same PR as `api-spec.md` |
