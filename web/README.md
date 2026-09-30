# QRGUARD Web App (React + Vite + TypeScript)

A thin client for the QRGUARD backend: **every security decision is made by the backend**
(`docs/architecture.md` D1). The web app sends the user's input and displays the explained result.

Pages: Home (with live backend status), Check a link, Check a message, Check a screenshot,
Check a QR code (upload **or live camera scan**: the browser only decodes the code, the backend
analyses it), Make a QR (generated **in the browser**, so Wi-Fi passwords never leave the device),
Safety tips, About, and with sign-in: **Account & privacy** (save-history switch, delete my data),
**History** (verdicts only; details, delete one/all, pagination), **report a wrong result** (on
every result) and **Admin** (anonymous daily statistics, provider status, review user reports; the
backend enforces the admin claim).

## Sign-in modes (`VITE_AUTH_MODE`)

| Mode | Use | Backend |
|---|---|---|
| `firebase` | Production: anonymous ("Continue without an e-mail") or e-mail/password via Firebase Auth | `FIREBASE_PROJECT_ID` set |
| `dev` | Local demo without a Firebase project: "Demo sign-in" with any name (tick "administrator" for the admin page) | `AUTH_DEV_TOKENS=true HISTORY_STORE=memory` (refused in production) |
| `off` | No sign-in; all checks still work, history is hidden | — |

For a full local stack with real Firebase sign-in but no Google account, use the Firebase emulators
(see `docs/testing.md`): `VITE_FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099` and a
`demo-*` project id.

## Requirements

- Node.js **20.19+** (22 LTS recommended) and npm
- The backend running locally (`backend/README.md`) or a deployed backend URL

## Run locally

```bash
cd QRGUARD/web
npm ci
cp .env.example .env.local        # VITE_API_BASE_URL=http://localhost:5000
npm run dev                       # http://localhost:5173
```

The backend must allow the web origin: `ALLOWED_ORIGINS=http://localhost:5173` (the backend default).

## Quality checks (same as CI, `.github/workflows/web-ci.yml`)

```bash
npm run lint        # ESLint (typescript-eslint strict, react-hooks, no dangerouslySetInnerHTML)
npm run typecheck   # tsc, strict mode
npm test            # Vitest + Testing Library (backend is stubbed; no network)
npm run coverage    # with coverage thresholds (80 % lines / functions / statements, 75 % branches)
npm run build       # production build in dist/
```

## Security rules for this app

- No security logic in the client; the backend validates everything again (file type and size
  checks here are only for convenience).
- Results are rendered as **plain text**: URLs and decoded QR content are never clickable links,
  and `dangerouslySetInnerHTML` is banned by lint.
- Requests are sent without cookies (`credentials: 'omit'`) and with `no-referrer`.
- `VITE_*` variables are public (compiled into the bundle): never put secrets in them.
- `vercel.json` sets a strict Content-Security-Policy and security headers for the deployed site
  (update `connect-src` to the real backend URL when deploying).

## Structure

```
src/
  main.tsx, router.tsx
  pages/        Dashboard, UrlCheck, MessageCheck, ScreenshotCheck, QrImageCheck, QrGenerator,
                SecurityTips, About, NotFound
  components/   Layout, CheckPage, ResultCard, AnalysisDetails, RiskBadge, ScoreGauge,
                IndicatorList, ThreatIntelStatus, FileDropzone, ErrorAlert
  services/     api.ts (fetch client, timeouts, error envelope)
  hooks/        useAnalysis.ts (one request at a time, cancel on leave)
  types/        api.ts (mirrors docs/api-spec.md)
  utils/        format.ts (display only), qrPayload.ts (QR generator payloads)
```
