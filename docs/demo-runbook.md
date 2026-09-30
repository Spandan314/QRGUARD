# Final demonstration runbook (Android + web)

A step-by-step script for the final demonstration, using only **DEMO / TEST DATA**. Every
expected result below is checked automatically: `python -m scripts.demo_kit --check` (in
`backend/`, also run by `tests/unit/test_demo_kit.py`) sends each input through the real API and
fails if a result changes.

## What to prepare

| Item | Where |
|---|---|
| Printed QR sheet (or a second screen showing it) | `demo-data/demo-kit/index.html` (5 codes with expected results). Rebuild: `cd backend && python -m scripts.demo_kit --write ../demo-data/demo-kit` |
| Screenshot files for the web upload | `postman/fixtures/scam-kyc.png`, `postman/fixtures/genuine-otp.png` |
| Android phone with the **preview APK** installed | `eas build -p android --profile preview` (docs/deployment.md §4) |
| Laptop browser on the Vercel URL | docs/deployment.md §3 |
| Admin account (e-mail/password, `set-admin` done) | docs/deployment.md §1 "Admin accounts" |
| Evaluation table | docs/evaluation.md |

### The day before

1. `python scripts/smoke_test.py https://<service>.onrender.com --web-origin https://<app>.vercel.app` → all pass.
2. On the phone: open the app → **Sign in** tab → *Continue without an e-mail* → scan QR 1 → it
   works end to end. Then **Account → Delete my data** so the demo starts with an empty history.
3. Charge the phone; turn on "stay awake" (Developer options) and set screen brightness high
   (helps the laptop webcam and projector).

### Ten minutes before

1. Wake the free Render instance: open `https://<service>.onrender.com/api/health` and wait for
   the JSON (up to a minute).
2. Open the web app, sign in with the **admin** e-mail account in one browser window, and keep a
   private window ready for a fresh anonymous user.
3. On the phone, sign in anonymously and switch **Offer to save my results** on (Account tab).

## The demonstration (≈ 12 minutes)

| # | Where | Do | Expected result | Say |
|---|---|---|---|---|
| 1 | Phone | Home → **Scan a QR code** → QR 1 | ✅ SAFE · **VERIFIED** (trusted domain) | The link is never opened automatically; "Open" asks first. |
| 2 | Phone | Scan QR 2 | ⚠️ SUSPICIOUS (50) | Brand name in a domain it does not own, risky TLD, phishing words. Each reason is listed. |
| 3 | Phone | Scan QR 3 | ⛔ MALICIOUS (90) · **Verified by threat intelligence** | A threat-list hit is decisive. (Demo blocklist; real providers switch on with API keys.) |
| 4 | Phone | Scan QR 4 ("refund" UPI) | ⚠️ SUSPICIOUS (40) | Scanning a UPI QR only ever **sends** money; pre-filled amount and a refund pretext. |
| 5 | Phone | Scan QR 5 (shop UPI) | ✅ SAFE · UNVERIFIED | SAFE is **not** a guarantee: the app says so. |
| 6 | Phone | Home → **Check a message** → paste the genuine OTP SMS below | ✅ SAFE | "Never share your OTP" is recognised as genuine advice. |
| 7 | Phone | Home → **Check a message** → fake KYC SMS below | ⛔ MALICIOUS (65) | Threat + urgency + look-alike link combine; the breakdown shows points per source. |
| 8 | Web | **Link** → `https://amaz0n-offers.example/deal` | ⛔ MALICIOUS (60) | Typosquatting: "0" instead of "o". |
| 9 | Web | **Message** → fake internship text below | ⛔ MALICIOUS (60) | Job offer + fee. |
| 10 | Web | **Screenshot** → upload `scam-kyc.png` | ⛔ MALICIOUS (65) | OCR reads the text; the image and text are discarded after analysis. |
| 11 | Web | **Screenshot** → upload `genuine-otp.png` | ✅ SAFE | |
| 12 | Web | **QR code → Use the camera** → hold QR 4 to the webcam | ⚠️ SUSPICIOUS | Same backend, same verdict on both apps. |
| 13 | Web | **Make a QR** → Wi-Fi → *Create QR code* | QR image appears | A utility, separate from detection. |
| 14 | Phone | **History** tab | The saved verdicts; links show only the domain | No message text, screenshot or full link is stored; delete one / all. |
| 15 | Web (private window) | Continue without e-mail → **History** | "No saved results yet." | Each user sees only their own history. |
| 16 | Web | On a result: **Is this result wrong? Report it** → send | "Thank you – your report was sent…" | |
| 17 | Web (admin window) | **Admin** | Check counts; the report; **Mark as reviewed** | Only accounts with the admin claim; a normal user is refused. |
| 18 | Phone | **Account → Delete my data** → confirm | History empty, signed out | Right to erasure; history also expires after 90 days (hidden, then deleted at next sign-in or by the admin purge; free plan, no paid TTL). |
| 19 | Slides | docs/evaluation.md | Held-out precision/recall and the four known errors | Honest numbers, including failures. |

Messages to paste (from `demo-data/messages.yaml`):

- **Genuine OTP (#6):** `482913 is your OTP for login to HDFC Bank NetBanking. OTP valid for 5 mins. Never share your OTP with anyone. -HDFC Bank`
- **Fake KYC (#7):** `Dear customer, your SBI account will be BLOCKED today. Update your KYC immediately: http://sbi-kyc-update.xyz/login`
- **Fake internship (#9):** `You are selected for our internship with stipend and certificate. Pay the registration fee of Rs 1,500 within 24 hours to confirm your seat.`

Tip: send these to the phone beforehand (e.g. a note or a message to yourself) and copy them from
there; do not send them to anyone else.

## Optional: security demo (Postman)

`npx newman run postman/QRGUARD.postman_collection.json --working-dir postman` against a **local**
backend (see docs/testing.md; it needs relaxed rate limits and dev tokens, which production refuses).
It shows SSRF blocking, oversized/fake uploads (413/415), validation errors and rate limiting (429).
Do not point it at the production backend.

## If something goes wrong

| Symptom | Fix |
|---|---|
| "Cannot reach the QRGUARD server" on the first check | The Render instance was asleep: wait 30–60 s and retry. |
| Screenshot check says it is temporarily unavailable | OCR missing on the host: the smoke test prints `OCR engine`. Skip #10–11 or use the local fallback. |
| Sign-in fails on the web | The Vercel domain is missing from Firebase *Authorized domains*. |
| Web shows a CORS / network error | `ALLOWED_ORIGINS` on Render must be exactly the Vercel origin (`https://…`, no trailing slash). |
| Camera does not start in the browser | Allow the camera for the site; it only works over HTTPS (or localhost). |
| Admin page refused for the admin | Sign out and in again after `set-admin`. |

### Local fallback (no internet needed for the analysis)

On the laptop (backend + web on the same Wi-Fi as the phone):

```bash
# terminal 1: backend with demo accounts (never in production)
cd backend && AUTH_DEV_TOKENS=true HISTORY_STORE=memory ALLOWED_ORIGINS=http://localhost:5173 \
  flask --app wsgi run --host 0.0.0.0 --port 5000
# terminal 2: web app with demo accounts
cd web && VITE_API_BASE_URL=http://localhost:5000 VITE_AUTH_MODE=dev npm run dev
# terminal 3: phone via Expo Go (same Wi-Fi); use the laptop's LAN IP
cd mobile && EXPO_PUBLIC_API_BASE_URL=http://<laptop-LAN-IP>:5000 EXPO_PUBLIC_AUTH_MODE=dev npx expo start
```

The phone runs the app in **Expo Go** (scan the terminal's QR code); plain HTTP to the laptop is
fine there. Demo accounts replace Firebase; everything else (analysis, threat intelligence,
scoring, history, admin with a `dev-admin-…` account) behaves the same.
