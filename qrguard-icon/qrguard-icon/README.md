# QRGUARD app icon: "Sealed scan", teal tile

Colours: teal `#34E0B4` background, ink `#0A0F14` symbol.

## app/
- `icon-1024.png`: the main icon. Square, no rounded corners, no transparency
  (iOS and Android round the corners themselves). Use it for the App Store and
  as the main app icon in Expo / React Native / Flutter.
- `icon-master.svg`: the source vector, if you ever need another size.

## android/
- `adaptive-foreground-1024.png` (and the 432 px version): the symbol on transparent,
  kept inside the 66% safe zone so circle/squircle masks never crop it.
- `adaptive-background-1024.png`: plain teal background layer.
  (Or just set the background colour to `#34E0B4`.)
- `monochrome-1024.png`: white symbol for Android 13+ themed icons.
- `play-store-512.png`: the Google Play listing icon.

Expo example (app.json):

    "icon": "./assets/icon-1024.png",
    "android": {
      "adaptiveIcon": {
        "foregroundImage": "./assets/adaptive-foreground-1024.png",
        "backgroundColor": "#34E0B4",
        "monochromeImage": "./assets/monochrome-1024.png"
      }
    }

## web/
Put these in the website's `public/` folder, then in `index.html` `<head>`:

    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="icon" href="/favicon.ico" sizes="any">
    <link rel="apple-touch-icon" href="/apple-touch-icon.png">
    <meta name="theme-color" content="#34E0B4">

For a web app manifest (PWA): `icon-192.png`, `icon-512.png` and
`icon-maskable-512.png` (with `"purpose": "maskable"`).

The favicon uses a slightly bolder symbol so it stays clear at 16 px.
