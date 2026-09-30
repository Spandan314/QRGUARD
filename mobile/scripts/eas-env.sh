#!/usr/bin/env bash
# Sets every EAS environment variable the QRGUARD Android builds need, in both the `preview` and
# `production` EAS environments (docs/deployment.md §4). Safe to re-run: `eas env:set` creates or
# updates. All values are public identifiers (EXPO_PUBLIC_* and IDs), never secrets.
#
# Run from mobile/ after `eas login` and `eas init`:
#   EAS_PROJECT_ID=<id from eas init> \
#   API_BASE_URL=https://<service>.onrender.com \
#   FIREBASE_API_KEY=<apiKey> FIREBASE_AUTH_DOMAIN=<authDomain> \
#   FIREBASE_PROJECT_ID=<projectId> FIREBASE_APP_ID=<appId> \
#   bash scripts/eas-env.sh            # add --dry-run to print the commands without running them
set -euo pipefail

DRY_RUN=0
[ "${1:-}" = "--dry-run" ] && DRY_RUN=1
EAS="${EAS_BIN:-eas}"

fail() { echo "eas-env: $*" >&2; exit 2; }

for name in EAS_PROJECT_ID API_BASE_URL FIREBASE_API_KEY FIREBASE_AUTH_DOMAIN FIREBASE_PROJECT_ID FIREBASE_APP_ID; do
  [ -n "${!name:-}" ] || fail "$name is not set (see the usage at the top of this script)"
done

# Release builds must reach the deployed backend over HTTPS (Android blocks plain HTTP), and a local
# or emulator address would produce an APK that cannot connect on a real phone.
[[ "$API_BASE_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] ||
  fail "API_BASE_URL must look like https://<service>.onrender.com (https, no path, no trailing slash)"
[[ "$API_BASE_URL" =~ localhost|127\.0\.0\.1|10\.0\.2\.2|0\.0\.0\.0 ]] &&
  fail "API_BASE_URL points to a local/emulator address; use the deployed backend"
[[ "$EAS_PROJECT_ID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ||
  fail "EAS_PROJECT_ID must be the UUID printed by 'eas init'"
[[ "$FIREBASE_PROJECT_ID" =~ ^[a-z][a-z0-9-]{4,29}$ ]] ||
  fail "FIREBASE_PROJECT_ID must look like 'qrguard-demo'"
[[ "$FIREBASE_PROJECT_ID" == demo-* ]] &&
  fail "FIREBASE_PROJECT_ID is an emulator-only 'demo-' project; use the real Firebase project"

set_var() {
  local environment=$1 name=$2 value=$3
  local cmd=("$EAS" env:set "$environment" --name "$name" --value "$value" --visibility plaintext --non-interactive)
  if [ "$DRY_RUN" = 1 ]; then
    echo "${cmd[*]}"
  else
    "${cmd[@]}" >/dev/null
    echo "set $name in $environment"
  fi
}

for environment in preview production; do
  set_var "$environment" EAS_PROJECT_ID "$EAS_PROJECT_ID"
  set_var "$environment" EXPO_PUBLIC_API_BASE_URL "$API_BASE_URL"
  set_var "$environment" EXPO_PUBLIC_FIREBASE_API_KEY "$FIREBASE_API_KEY"
  set_var "$environment" EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN "$FIREBASE_AUTH_DOMAIN"
  set_var "$environment" EXPO_PUBLIC_FIREBASE_PROJECT_ID "$FIREBASE_PROJECT_ID"
  set_var "$environment" EXPO_PUBLIC_FIREBASE_APP_ID "$FIREBASE_APP_ID"
done

[ "$DRY_RUN" = 1 ] || echo "Done. Next: EAS_PROJECT_ID=$EAS_PROJECT_ID eas build -p android --profile preview"
