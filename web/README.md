# QRGUARD Web App (React + Vite + TypeScript)

A thin client for the QRGUARD backend: **every security decision is made by the backend**
(`docs/architecture.md` D1). The web app sends the user's input and displays the explained result.

Pages: Home (with live backend status), Check a link, Check a message, Check a screenshot,
Check a QR image, Make a QR (generated **in the browser**, so Wi-Fi passwords never leave the
device), Safety tips, About. History, login and admin pages arrive with Firebase (Phase 10).

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
