# Deployment

QRGUARD is deployed as four pieces that only talk to each other over HTTPS:

| Piece | Where | Configured by | What it holds |
|---|---|---|---|
| Backend (Flask + Gunicorn, Docker) | Render | `render.yaml`, `backend/Dockerfile` | All analysis, threat intelligence, scoring, token verification, history. **All secrets live here.** |
| Web app (React + Vite) | Vercel | `web/vercel.json` | Static files. Only public `VITE_*` values. |
| Mobile app (Expo) | EAS Build → APK / AAB | `mobile/eas.json`, `mobile/app.config.ts` | Only public `EXPO_PUBLIC_*` values. |
| Firebase project | Firebase | `firebase/firebase.json`, `firestore.rules`, `firestore.indexes.json` | Auth (sign-in), Firestore (history), rules, indexes, 90-day TTL. |

Nothing below needs a secret to be committed. Everything marked **secret** is entered only in the
Render dashboard (never in Vercel, EAS or the repository).

Deploy in this order: **Firebase → backend → web → mobile**. Each step needs a URL or ID from the
step before it. Deploy from the branch that contains the merged release (`main` after the
`develop → main` release merge; `develop` is fine for a staging/demo deployment).

### Guards built into the repository

The repository refuses the most common deployment mistakes instead of shipping a broken build:

| Where | Refuses |
|---|---|
| Backend (`APP_ENV=production`) | `ALLOWED_ORIGINS=*`; `AUTH_DEV_TOKENS=true`; `HISTORY_STORE=memory`; an unreadable service-account key (reported without printing it) |
| Web build on Vercel (`VERCEL=1`) | `VITE_API_BASE_URL` that is missing or not `https://`; `VITE_AUTH_MODE=dev`; `VITE_FIREBASE_AUTH_EMULATOR_HOST` |
| EAS `preview` / `production` builds | `EXPO_PUBLIC_API_BASE_URL` that is missing or not `https://` (Android release builds block plain HTTP) |

---

## 1. Firebase

1. Create a project in the [Firebase console](https://console.firebase.google.com) (for example
   `qrguard-demo`). The Spark (free) plan is enough.
2. **Build → Authentication → Get started → Sign-in method:** enable **Anonymous** and
   **Email/Password**.
3. **Build → Firestore Database → Create database** → *Standard edition*, **production mode**,
   location `asia-south1` (Mumbai) or the region closest to your users.
4. Deploy the security rules, the index, and the **90-day TTL policy** from this repository:
   ```bash
   cd firebase
   npm ci
   npx firebase login
   npm run deploy -- --project <project-id>
   ```
   - The rules let a signed-in user read and delete only their own scans. Clients can never
     write scans, reports or stats: only the backend (Admin SDK) does. Tested in
     `firebase/tests/rules.test.js` (`npm run test:rules`).
   - `firestore.indexes.json` enables TTL on `scans.expire_at` (each saved scan expires 90 days
     after it was saved) and excludes that field from indexing, as Google recommends for TTL
     fields. Check **Firestore → TTL**: the `scans` / `expire_at` policy moves from *Creating*
     to *Serving* within minutes to hours. Firestore usually deletes expired documents within
     24 hours of `expire_at`.
5. **Service account for the backend (secret).** Project settings → Service accounts →
   *Generate new private key*. Keep the JSON file outside the repository (`.gitignore` also
   blocks `*service-account*.json` and `firebase-adminsdk*.json`). You upload it to Render in
   step 2.
6. **Web and mobile app config (public).** Project settings → *Your apps* → add a **Web** app
   (the Android app uses the same web SDK config; no `google-services.json` is needed). Copy
   `apiKey`, `authDomain`, `projectId` and `appId`. These are public identifiers, not secrets:
   every API request is still checked by the backend verifying the ID token.
7. **Restrict the browser API key** (recommended). Google Cloud console → *APIs & Services →
   Credentials* → the key named *Browser key (auto created by Firebase)* → *API restrictions* →
   restrict to **Identity Toolkit API** and **Token Service API**. Leave *Application
   restrictions* at *None*: the Android app uses the same key without a referrer.

### Admin accounts

Admin access (`/api/admin/*`, the web Admin page) is a Firebase custom claim `admin: true`.
Only a person with the service-account key can set it:

```bash
cd backend
python -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt   # once
export FIREBASE_PROJECT_ID=<project-id>
export FIREBASE_CREDENTIALS_FILE=/path/to/service-account.json
flask --app wsgi set-admin <uid>            # grant
flask --app wsgi set-admin <uid> --revoke   # remove
```

Find the uid in Firebase console → Authentication → Users (*User UID* column). Create the admin
account with **e-mail and password** (an anonymous account is lost when its browser data is
cleared). The user must sign out and in again to receive the new claim.

---

## 2. Backend on Render

`render.yaml` (repository root) is a Render Blueprint. It holds variable **names** and safe
defaults only; every secret is `sync: false`, so Render asks for it.

1. Render dashboard → **New → Blueprint** → connect this GitHub repository → branch `main`
   (or `develop` for a staging demo).
2. Fill in the prompted values:

   | Variable | Value |
   |---|---|
   | `ALLOWED_ORIGINS` | your Vercel URL(s), comma-separated, exact origins, e.g. `https://qrguard.vercel.app`. You can put a placeholder such as `https://example.invalid` now and correct it after step 3. `*` is refused. |
   | `FIREBASE_PROJECT_ID` | the Firebase project ID. Leave empty to run without sign-in/history (analysis still works; history answers 503). |
   | `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `PHISHTANK_API_KEY` | **secret**, optional. Empty = provider disabled; the demo blocklist still works. |

3. Service **qrguard-api → Environment → Secret Files → Add**: file name
   `firebase-service-account.json`, contents = the JSON from Firebase step 5. Render mounts it at
   `/etc/secrets/firebase-service-account.json`, which is what `FIREBASE_CREDENTIALS_FILE`
   points to. If the first deploy started before you added the file and failed with a
   service-account error, click **Manual Deploy → Deploy latest commit**.
4. Render builds `backend/Dockerfile` (Python 3.12 slim + Tesseract OCR, non-root user,
   Gunicorn 2 workers × 4 threads on Render's `$PORT`) and waits for `/api/health`.
5. Smoke-test the deployment (no credentials needed; nothing is saved):
   ```bash
   cd backend
   python scripts/smoke_test.py https://<service>.onrender.com --web-origin https://<your-app>.vercel.app
   ```
   It checks health (OCR engine and enabled providers are printed), security headers, a
   blocklisted link, a scam message, a UPI QR, SSRF protection, input validation, that history
   needs sign-in, that demo tokens are refused, and CORS for your origin and a foreign one.

Notes:
- `TRUST_PROXY_HOPS=1` makes rate limits use the real client IP behind Render's proxy.
- The free plan sleeps after 15 minutes idle; the first request then takes ~30–60 s and the apps
  may show "Cannot reach the QRGUARD server" once. Before a demo, open
  `https://<service>.onrender.com/api/health` and wait for the JSON.
- Rate limits are per Gunicorn worker (`memory://`). For shared limits set
  `RATELIMIT_STORAGE_URI` to a Redis URL.
- Optional: download public blocklists with `flask --app wsgi ti-update-feeds` (needs
  `THREAT_INTEL_FEED_DIR`). Without it, only the demo blocklist is used, and results say so.

### Other Docker hosts

The same image runs anywhere:

```bash
cd backend
docker build -t qrguard-backend .
docker run -p 5000:5000 -e APP_ENV=production -e ALLOWED_ORIGINS=https://your-web-app \
  -e TRUST_PROXY_HOPS=1 qrguard-backend
```

---

## 3. Web app on Vercel

1. Vercel → **Add New… → Project** → import the repository → **Root Directory: `web`**. The
   framework, install/build commands and output folder come from `web/vercel.json`.
2. **Settings → Environment Variables** (all public, compiled into the bundle). Tick
   **Production** and **Preview**; a hosted build without a valid `VITE_API_BASE_URL` is refused.

   | Variable | Value |
   |---|---|
   | `VITE_API_BASE_URL` | `https://<service>.onrender.com` |
   | `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, `VITE_FIREBASE_APP_ID` | from Firebase step 6 |

3. Deploy. `web/vercel.json` adds the SPA rewrite, long-lived caching for hashed assets and the
   security headers (CSP, `camera=(self)` for QR scanning, no framing). The CSP allows API calls
   to `https://*.onrender.com` and Firebase Auth; if the backend is hosted elsewhere, add its
   origin to `connect-src`. The E2E suite runs the web app under exactly these headers.
4. Finish the loop:
   - Render → `ALLOWED_ORIGINS` = the production Vercel URL (choose **Save and deploy**).
   - Firebase → Authentication → **Settings → Authorized domains** → add the Vercel domain.
   - Re-run the smoke test with `--web-origin https://<your-app>.vercel.app`.

Vercel *preview* URLs change per deployment; add one to `ALLOWED_ORIGINS` only if you need to
test a preview against the production backend.

---

## 4. Android app with EAS

The phone talks to the backend directly (CORS does not apply to native apps). Release builds
must use the `https://` Render URL: `app.config.ts` stops a `preview`/`production` build that
has anything else.

```bash
cd mobile
npm ci
npm install -g eas-cli
eas login
eas init        # creates the Expo project and prints its ID ("projectId")
```

`app.config.ts` is dynamic, so `eas init` cannot write the ID into it; it is read from the
`EAS_PROJECT_ID` variable instead (an identifier, not a secret). One command sets it and the five
public app values in both the `preview` and `production` EAS environments. It refuses a non-HTTPS,
local or emulator backend URL and a malformed ID, and can be re-run safely (`eas env:set`):

```bash
EAS_PROJECT_ID=<projectId printed by eas init> \
API_BASE_URL=https://<service>.onrender.com \
FIREBASE_API_KEY=<apiKey> FIREBASE_AUTH_DOMAIN=<authDomain> \
FIREBASE_PROJECT_ID=<projectId> FIREBASE_APP_ID=<appId> \
bash scripts/eas-env.sh          # add --dry-run first to see the 12 commands it will run

export EAS_PROJECT_ID=<same projectId>      # the local shell also needs it for `eas build`
eas build -p android --profile preview      # installable APK (demo / testers)
eas build -p android --profile production   # AAB for the Play Store (version code auto-increments)
```

`eas.json` maps each build profile to the EAS environment of the same name. If the release guard
reports a missing URL while building, check `eas env:list --environment preview`.

Install the APK from the link or QR code EAS prints (allow "Install unknown apps" for the
browser). Permissions: camera only (QR scanning); photos use the system picker.

---

## 5. Go-live checklist

- [ ] `python scripts/smoke_test.py <backend> --web-origin <web>` → all checks pass, OCR `available`.
- [ ] Web app loads over HTTPS; the browser console shows no CSP or CORS errors.
- [ ] Anonymous sign-in works; checking with "Save to my history" shows the scan on History.
- [ ] A second account cannot see the first account's history.
- [ ] A non-admin gets "Administrator access is required"; the admin (after `set-admin`) sees stats.
- [ ] "Delete my data" removes history and the account.
- [ ] Render logs contain no URLs, message text, OCR text or tokens (request logs show only
      method, path, status and duration).
- [ ] Firestore → TTL shows `scans` / `expire_at` as *Serving*.
- [ ] The APK installs; the camera scans the demo QR codes (`demo-data/demo-kit/index.html`) and
      results match the web app.

## What was verified in development

- `backend/Dockerfile` built and run as a production container (`APP_ENV=production`, Gunicorn,
  uid 10001): health, analysis, CORS allow-listing, the production refusal of dev tokens, and a
  graceful `OCR_UNAVAILABLE` when Tesseract is missing. (The Tesseract `apt` layer could not be
  fetched from the development sandbox; CI and Render can reach Debian's mirrors.)
- The same container against the Firebase **Auth and Firestore emulators**, with real Firebase
  ID tokens: save to history, per-user isolation, admin 403, delete my data, and logs free of
  URLs and tokens.
- `scripts/smoke_test.py` against a production-mode Gunicorn server (11/11), including detection
  of a wrong CORS origin.
- The full browser E2E suite (`e2e/`), with the web app served under `web/vercel.json`'s real
  security headers.
- `firestore.indexes.json` (TTL override) validated with firebase-tools' own deploy validator.
- The web and EAS build guards (a hosted build without an `https://` API URL is refused).

What needs real accounts and cannot be verified from the repository: the Render, Vercel and
EAS deploys, a real Firebase project (rules/TTL deploy, service account), real
threat-intelligence API keys, and camera scanning on a physical phone.
