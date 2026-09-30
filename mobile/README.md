# QRGUARD Mobile App (React Native + Expo SDK 57, TypeScript)

A thin client for the QRGUARD backend: **every security decision is made by the backend**
(`docs/architecture.md` D1). The app sends what the user scans, types or picks, and explains the
result.

Screens (Expo Router, `src/app/`):

| Screen | Route | Notes |
|---|---|---|
| Home | `/(tabs)/index` | Action cards, live backend status |
| About & settings | `/(tabs)/settings` | Server, how it decides, privacy, 1930 helpline |
| Scan a QR code | `/scan/camera` | `CameraView` QR scanning, **scans once, never opens the code** |
| QR code from a photo | `/scan/image` | Gallery image → `/api/analyze/qr` |
| Check a link | `/check/url` | Paste button |
| Check a message | `/check/message` | "We do not store message text" |
| Check a screenshot | `/check/screenshot` | Gallery image → OCR on the server |
| Make a QR code | `/generate` | **Utility**, visually separate, generated on the phone, share/save |
| Result | `/result` | Level (icon + word + colour), score, verification, "why", advice, TI status, `OpenLinkGuard` |

History and sign-in arrive with Firebase (Phase 10).

## Run it

```bash
cd QRGUARD/mobile
npm ci
cp .env.example .env        # EXPO_PUBLIC_API_BASE_URL=http://<your computer's LAN IP>:5000
npx expo start              # scan the QR code with Expo Go (Android/iOS)
```

The phone must reach the backend: start it with `flask --app wsgi run --host 0.0.0.0` and use your
computer's LAN IP (Android emulator: `http://10.0.2.2:5000`). `localhost` on a phone is the phone.
Camera scanning works in Expo Go; `npm run web` runs the same screens in a browser (no camera).

Builds (EAS, `eas.json`): `eas build -p android --profile preview` produces an installable APK.

## Quality checks (same as CI, `.github/workflows/mobile-ci.yml`)

```bash
npm run lint        # eslint-config-expo + security rules
npm run typecheck   # tsc --noEmit, strict
npm test            # Jest (jest-expo) + React Native Testing Library, backend stubbed
npm run coverage    # with coverage thresholds
npx expo export --platform android   # proves the app bundles
```

## Security and privacy rules

- **OpenLinkGuard** (`src/components/OpenLinkGuard.tsx`) is the only code that opens external
  links; lint forbids `Linking` anywhere else. SAFE → confirm dialog showing the full URL.
  SUSPICIOUS → warning dialog. MALICIOUS → "Copy link"; opening needs two explicit confirmations.
  `intent:`, `javascript:`, `data:`, `file:`, `upi:` … are never opened (`src/utils/links.ts`).
- A scanned QR code is sent to the backend as text and never acted on by the app.
- Results travel through `ResultContext`, never route params (they would end up in logs).
- Permissions: camera only (no audio, location or contacts). The photo picker needs no storage
  permission.
- The QR generator runs on the phone: Wi-Fi passwords never leave the device.
- `EXPO_PUBLIC_*` values are public (compiled into the app): never put secrets there.
- Accessibility: icon + word + colour for every level, ≥ 44 pt touch targets, labelled controls,
  system font scaling.

## Notes on the setup

Dependency versions follow Expo SDK 57's compatibility table
(`node_modules/expo/bundledNativeModules.json`). Use `npx expo install <package>` to add packages.
