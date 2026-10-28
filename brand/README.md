# QRGUARD brand

![QRGUARD mark](qrguard-mark.svg)

**The mark** is a shield holding a QR code, crossed by an amber scan line. The QR code is the thing being checked, the shield stands for protection, and the scan line shows that QRGUARD inspects the code rather than promising it is safe. There is deliberately no tick mark, because a result can be SUSPICIOUS, MALICIOUS or NOT VERIFIED.

The mark is drawn on a 120 × 120 grid with 4-unit QR modules (three finder patterns and a few data modules). `marks.mjs` holds the single source drawing.

## Colours

| Role | Hex | Notes |
|---|---|---|
| Brand teal (shield top, wordmark) | `#0f766e` | teal-700; 5.5:1 on white |
| Shield bottom | `#134e4a` | teal-900 |
| Scan line | `#fbbf24` | amber-400; used only in the mark, never for verdicts |
| Ink ("QR" in the wordmark, text) | `#0f172a` | slate-900 |
| App icon background | `#f0fdfa` | teal-50 |
| Dark-mode wordmark | `#2dd4bf` | teal-400 on slate-900 |

The verdict colours (green, amber `#d97706`, red, grey) keep their meaning in results and are not brand colours.

## Wordmark and type

The wordmark is "**QR**GUARD" as live text in the platform's system sans-serif, extra-bold, with slightly tight letter-spacing. "QR" is set in ink and "GUARD" in brand teal. Because it is text, it stays readable by screen readers, and there is no web font to load or allow in the Content-Security-Policy.

## Files

| File | Use |
|---|---|
| `qrguard-mark.svg` | Master full-colour mark |
| `qrguard-mark-mono.svg` | One-colour mark (QR and scan line cut out) |
| `web/public/qrguard-mark.svg` | Web header logo |
| `web/public/favicon.svg`, `favicon-32.png` | Favicon (simplified: no data modules) |
| `web/public/apple-touch-icon.png` | iOS home-screen icon (180 px) |
| `mobile/assets/icon.png` | App icon (1024 px) |
| `mobile/assets/android-icon-foreground.png`, `-background.png`, `-monochrome.png` | Android adaptive and themed icon (1024 px; the mark sits inside the safe zone) |
| `mobile/assets/splash-icon.png` | Splash image (not wired up yet: the app has no `expo-splash-screen` plugin) |
| `mobile/assets/favicon.png` | Expo web favicon |
| `mobile/src/constants/brandMark.ts` | The mark as an SVG string for the app header |

## Regenerating

Edit `marks.mjs`, then, from the repo root (needs `npm ci` in `e2e/` and a Chromium binary):

```bash
CHROMIUM_PATH=/path/to/chrome node brand/render.mjs
```
