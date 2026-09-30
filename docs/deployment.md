# Deployment

QRGUARD is deployed as four pieces that only talk to each other over HTTPS:

| Piece | Where | What it holds |
|---|---|---|
| Backend (Flask + Gunicorn, Docker) | Render (`render.yaml`) | All analysis, threat intelligence, scoring, token verification, history. **All secrets live here.** |
| Web app (React + Vite) | Vercel (`web/vercel.json`) | Static files. Only public `VITE_*` values. |
| Mobile app (Expo) | EAS Build → APK / AAB | Only public `EXPO_PUBLIC_*` values. |
| Firebase project | Firebase console | Auth (sign-in), Firestore (history), rules, indexes, TTL. |

Nothing below needs a secret to be committed. Everything marked **secret** is typed into a
dashboard (Render, never Vercel or EAS).

Deploy in this order: **Firebase → backend → web → mobile**. Each step needs a URL or ID
from the step before it.

---

## 1. Firebase

1. Create a project in the [Firebase console](https://console.firebase.google.com) (for example
   `qrguard-demo`). The Spark (free) plan is enough.
2. **Authentication → Sign-in method:** enable **Anonymous** and **Email/Password**.
   **Authentication → Settings → Authorized domains:** add your Vercel domain.
3. **Firestore Database → Create database** (production mode; region `asia-south1` for India).
4. Deploy the rules and indexes from this repository:
   ```bash
   cd firebase
   npm ci
   npx firebase login
   npx firebase deploy --only firestore:rules,firestore:indexes --project <project-id>
   ```
   The rules let a signed-in user read and delete only their own scans. Clients can never
   write scans, reports or stats: only the backend (Admin SDK) does. They are tested in
   `firebase/tests/rules.test.js` (`npm run test:rules`).
5. **TTL (automatic deletion after 90 days).** Each scan stores `expire_at`. Firestore TTL policies
   cannot be set from `firebase.json`, so turn it on once:
   - Console: Firestore → **TTL** → *Create policy* → collection group `scans`, field `expire_at`; or
   - `gcloud firestore fields ttls update expire_at --collection-group=scans --enable-ttl --project <project-id>`

   Firestore deletes expired documents within about 24 hours after `expire_at`.
6. **Service account for the backend (secret).** Project settings → Service accounts →
   *Generate new private key*. Keep the JSON file outside the repository (`.gitignore` also
   blocks `*service-account*.json` and `firebase-adminsdk*.json`). You will upload it to Render
   in step 2.
7. **Web and mobile app config (public).** Project settings → *Your apps* → add a Web app. Copy
   `apiKey`, `authDomain`, `projectId` and `appId`. These are public identifiers, not secrets:
   every request is still checked by the backend verifying the ID token.

### Admin accounts

Admin access (`/api/admin/*`, the web Admin page) is a Firebase custom claim `admin: true`.
Only a person with the service-account key can set it:

```bash
cd backend
export FIREBASE_PROJECT_ID=<project-id>
export FIREBASE_CREDENTIALS_FILE=/path/to/service-account.json
flask --app wsgi set-admin <uid>            # grant
flask --app wsgi set-admin <uid> --revoke   # remove
```

Find the uid in Firebase console → Authentication → Users (*User UID* column). The user must
sign out and in again to receive the new claim.

---

## 2. Backend on Render

The repository root contains `render.yaml` (a Render Blueprint). It holds variable **names** and
safe defaults only; every secret is `sync: false`, so Render asks for it.

1. Render dashboard → **New → Blueprint** → select this repository and branch `main`.
2. Fill in the prompted values:

   | Variable | Value |
   |---|---|
   | `ALLOWED_ORIGINS` | your Vercel URL(s), comma-separated, e.g. `https://qrguard.vercel.app`. `*` is refused in production. |
   | `FIREBASE_PROJECT_ID` | the Firebase project ID. Leave empty to run without sign-in/history (analysis still works; history answers 503). |
   | `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `PHISHTANK_API_KEY` | **secret**, optional. Empty = provider disabled. |

3. Service → **Environment → Secret Files** → add `firebase-service-account.json` with the
   JSON from Firebase step 6. Render mounts it at `/etc/secrets/firebase-service-account.json`,
   which is what `FIREBASE_CREDENTIALS_FILE` points to.
4. Deploy. Render builds `backend/Dockerfile` (Python 3.12 slim + Tesseract OCR, non-root user,
   Gunicorn 2 workers × 4 threads, `$PORT` from Render) and checks `/api/health`.
5. Check it:
   ```bash
   curl https://<service>.onrender.com/api/health
   ```
   `components.ocr_engine` should be `available`, `scoring_config.status` `loaded`, and
   `threat_intel.providers` lists which providers are enabled (never the keys).

Production safety checks built into the backend (it refuses to start otherwise):
`ALLOWED_ORIGINS` may not be `*`; `AUTH_DEV_TOKENS` and `HISTORY_STORE=memory` are refused when
`APP_ENV=production`; an unreadable service-account key stops start-up without printing it.
`TRUST_PROXY_HOPS=1` makes rate limits use the real client IP behind Render's proxy.

Notes:
- The free plan sleeps after 15 minutes idle; the first request then takes ~30–60 s. The apps
  show "Cannot reach the QRGUARD server" after their timeout. For the demo, open `/api/health`
  a minute beforehand.
- Rate limits are per Gunicorn worker (`memory://`). For shared limits set
  `RATELIMIT_STORAGE_URI` to a Redis URL.
- Optional: download public blocklists at build time with `flask --app wsgi ti-update-feeds`
  (needs `THREAT_INTEL_FEED_DIR`). Without it, only the demo blocklist is used, and results say so.

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

1. Vercel → **Add New Project** → import the repository → **Root Directory: `web`**
   (framework preset: Vite; build `npm run build`; output `dist`).
2. Environment variables (all public, compiled into the bundle):

   | Variable | Value |
   |---|---|
   | `VITE_API_BASE_URL` | `https://<service>.onrender.com` |
   | `VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, `VITE_FIREBASE_APP_ID` | from Firebase step 7 |

   Do **not** set `VITE_AUTH_MODE=dev` or any emulator host in production.
3. `web/vercel.json` adds the SPA rewrite and security headers. Its Content-Security-Policy
   allows API calls to `https://*.onrender.com` and to Firebase Auth. If the backend is
   hosted elsewhere, add that origin to `connect-src`.
4. After the first deploy, put the final Vercel URL into the backend's `ALLOWED_ORIGINS` and
   into Firebase **Authorized domains**, then redeploy the backend.

---

## 4. Mobile app with EAS

The phone talks to the backend directly. CORS does not apply to native apps. Android release
builds refuse plain `http://`, so production must use the `https://` Render URL.

```bash
cd mobile
npm ci
npm install -g eas-cli
eas login
eas init                                   # links the project to your Expo account
# Public build-time values, stored in EAS (not in the repository):
eas env:create --environment preview --name EXPO_PUBLIC_API_BASE_URL --value https://<service>.onrender.com --visibility plaintext
eas env:create --environment preview --name EXPO_PUBLIC_FIREBASE_API_KEY --value <apiKey> --visibility plaintext
eas env:create --environment preview --name EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN --value <authDomain> --visibility plaintext
eas env:create --environment preview --name EXPO_PUBLIC_FIREBASE_PROJECT_ID --value <projectId> --visibility plaintext
eas env:create --environment preview --name EXPO_PUBLIC_FIREBASE_APP_ID --value <appId> --visibility plaintext
# repeat with --environment production for the store build

eas build -p android --profile preview      # installable APK (for the demo / testers)
eas build -p android --profile production   # AAB for the Play Store
```

`eas.json` profiles: `preview` = APK, internal distribution; `production` = app bundle.
Permissions requested: camera only (QR scanning). The photo picker uses the system picker.
Install the APK from the link EAS prints. Test on a device: scan a printed QR code, check a
link, a message and a screenshot, sign in, and see History.

---

## 5. Go-live checklist

- [ ] `GET /api/health` → `status: ok`, OCR `available`, scoring config `loaded`.
- [ ] Web app loads over HTTPS; the browser console shows no CSP or CORS errors.
- [ ] A browser on a different origin gets **no** `Access-Control-Allow-Origin` header.
- [ ] Anonymous sign-in works; checking with "Save to my history" shows the scan on History.
- [ ] A second account cannot see the first account's history.
- [ ] A non-admin gets 403 on the Admin page; the admin (after `set-admin`) sees stats.
- [ ] "Delete my data" removes history and the account.
- [ ] Render logs contain no URLs, message text, OCR text or tokens (request logs show only
      method, path, status and duration).
- [ ] The Firestore TTL policy on `scans.expire_at` shows as *Serving*.
- [ ] The APK installs, the camera scans a QR code, and results match the web app.

## What was verified in development

- `backend/Dockerfile` built and run as a production container (`APP_ENV=production`, Gunicorn,
  uid 10001): health, analysis, CORS allow-listing (foreign origin gets no CORS header), the
  production refusal of dev tokens, and a graceful `OCR_UNAVAILABLE` when Tesseract is missing.
- The same container against the Firebase **Auth and Firestore emulators**, with real Firebase
  ID tokens: save to history, per-user isolation, admin 403, delete my data, and logs free of
  URLs and tokens.
- The full browser E2E suite (`e2e/`) against backend + web + Expo web + emulators.

What needs real accounts and cannot be verified from the repository: the Render, Vercel and
EAS deploys, a real Firebase project (rules deploy, TTL, service account), real
threat-intelligence API keys, and camera scanning on a physical phone.
