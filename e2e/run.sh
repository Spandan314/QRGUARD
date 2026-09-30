#!/usr/bin/env bash
# End-to-end tests of the whole system, with no mocks:
#   Chromium -> web app / mobile app (Expo web export) -> Firebase Auth emulator
#            -> Flask backend (Gunicorn; verifies ID tokens) -> analysis, threat intelligence, scoring
#            -> Firestore emulator (history, reports, stats)
#
# Usage (from the repository root, after installing each part's dependencies):
#   bash e2e/run.sh             # web + mobile
#   bash e2e/run.sh web         # only the web app
# Needs: backend/.venv (pip install -r requirements-dev.txt), npm ci in web/, mobile/, firebase/, e2e/,
# Java 21+ for the Firestore emulator. CHROMIUM_PATH may point to a local Chromium.
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$E2E_DIR")"
BUILD="$E2E_DIR/.build"
export E2E_ARTIFACTS="${E2E_ARTIFACTS:-$E2E_DIR/artifacts}"
export PYTHON="${PYTHON:-$ROOT/backend/.venv/bin/python}"
export BACKEND_DIR="$ROOT/backend"
export FIREBASE_PROJECT_ID=demo-qrguard   # "demo-" projects never touch a real Firebase project
BACKEND_PORT=5095
export WEB_URL=http://localhost:4174
export MOBILE_URL=http://localhost:8083
TARGET="${1:-all}"

PIDS=()
cleanup() { [ ${#PIDS[@]} -eq 0 ] || kill "${PIDS[@]}" 2>/dev/null || true; }

inner() {
  # Runs inside `firebase emulators:exec`, which sets FIREBASE_AUTH_EMULATOR_HOST and FIRESTORE_EMULATOR_HOST.
  trap cleanup EXIT
  (
    cd "$BACKEND_DIR"
    APP_ENV=development HISTORY_STORE=firestore ALLOWED_ORIGINS="$WEB_URL,$MOBILE_URL" \
      RATELIMIT_ANALYZE="200 per minute" RATELIMIT_SCREENSHOT="60 per minute" PORT=$BACKEND_PORT \
      exec "$PYTHON" -m gunicorn -c gunicorn.conf.py wsgi:app
  ) >"$E2E_ARTIFACTS/backend.log" 2>&1 &
  PIDS+=($!)
  # The web build is served with web/vercel.json's production headers (CSP, Permissions-Policy).
  node "$E2E_DIR/static-server.mjs" "$BUILD/web" 4174 "$ROOT/web/vercel.json" \
    "http://127.0.0.1:$BACKEND_PORT http://127.0.0.1:9099" >"$E2E_ARTIFACTS/web-server.log" 2>&1 &
  PIDS+=($!)
  if [ "$TARGET" != web ]; then
    "$PYTHON" -m http.server 8083 --bind 127.0.0.1 --directory "$BUILD/mobile" >/dev/null 2>&1 &
    PIDS+=($!)
  fi
  for _ in $(seq 1 60); do curl -sf "http://127.0.0.1:$BACKEND_PORT/api/health" >/dev/null && break; sleep 1; done

  local status=0
  cd "$E2E_DIR"
  echo "== web app =="
  node tests/web.mjs || status=1
  if [ "$TARGET" != web ]; then
    echo "== mobile app (Expo web export) =="
    node tests/mobile.mjs || status=1
  fi

  echo "== privacy: backend log must not contain tokens, URLs or message text =="
  if grep -E "eyJ|E2ESECRET|Dear customer|secure-sbi-kyc-update|refund\.desk9912" "$E2E_ARTIFACTS/backend.log"; then
    echo "FAIL backend log leaks request content"
    status=1
  else
    echo "PASS backend log contains no tokens or request content"
  fi
  return $status
}

if [ "$TARGET" = "--inner" ]; then
  TARGET="${2:-all}"
  inner
  exit $?
fi

for dir in web mobile firebase e2e; do
  [ -d "$ROOT/$dir/node_modules" ] || { echo "Missing dependencies: run 'npm ci' in $dir/" >&2; exit 2; }
done
command -v "$PYTHON" >/dev/null || { echo "Missing backend virtualenv: set PYTHON or create backend/.venv" >&2; exit 2; }

for port in $BACKEND_PORT 4174 8083 9099 8085; do
  if curl -s -o /dev/null -m 2 "http://127.0.0.1:$port/"; then
    echo "Port $port is already in use: stop the process using it first" >&2
    exit 2
  fi
done

mkdir -p "$BUILD" "$E2E_ARTIFACTS"
"$PYTHON" "$E2E_DIR/make_y4m.py" "$BUILD/qr-refund.y4m"
export FAKE_CAMERA="$BUILD/qr-refund.y4m"

echo "Building the web app (Firebase mode, emulator)..."
(
  cd "$ROOT/web"
  VITE_API_BASE_URL="http://127.0.0.1:$BACKEND_PORT" VITE_AUTH_MODE=firebase \
    VITE_FIREBASE_API_KEY=demo-key VITE_FIREBASE_AUTH_DOMAIN=demo-qrguard.firebaseapp.com \
    VITE_FIREBASE_PROJECT_ID=demo-qrguard VITE_FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 \
    npx vite build --outDir "$BUILD/web" --emptyOutDir >/dev/null
)
if [ "$TARGET" != web ]; then
  echo "Exporting the mobile app for the web (Firebase mode, emulator)..."
  (
    cd "$ROOT/mobile"
    EXPO_PUBLIC_API_BASE_URL="http://127.0.0.1:$BACKEND_PORT" EXPO_PUBLIC_AUTH_MODE=firebase \
      EXPO_PUBLIC_FIREBASE_API_KEY=demo-key EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN=demo-qrguard.firebaseapp.com \
      EXPO_PUBLIC_FIREBASE_PROJECT_ID=demo-qrguard EXPO_PUBLIC_FIREBASE_AUTH_EMULATOR_HOST=127.0.0.1:9099 \
      npx expo export --platform web --output-dir "$BUILD/mobile" --clear >/dev/null
  )
fi

cd "$ROOT/firebase"
npx firebase emulators:exec --only auth,firestore --project demo-qrguard \
  "bash '$E2E_DIR/run.sh' --inner $TARGET"
