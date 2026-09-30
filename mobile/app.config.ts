import type { ExpoConfig } from 'expo/config'

// Only EXPO_PUBLIC_* values reach the app bundle, and they are public: never put secrets there.

// Release builds (EAS preview/production) must talk to the deployed HTTPS backend: Android
// blocks plain http:// in release builds, and the development default (10.0.2.2) would point at
// nothing on a real phone. Fail the build early instead of shipping an app that cannot connect.
const releaseProfile = ['preview', 'production'].includes(process.env.EAS_BUILD_PROFILE ?? '')
if (releaseProfile && !(process.env.EXPO_PUBLIC_API_BASE_URL ?? '').startsWith('https://')) {
  throw new Error(
    `EXPO_PUBLIC_API_BASE_URL must be the https:// backend URL for the "${process.env.EAS_BUILD_PROFILE}" build ` +
      '(set it with `eas env:create`, see docs/deployment.md).',
  )
}

// The Expo (EAS) project created by `eas init` for QRGUARD. A public identifier, not a secret.
// `eas init` cannot write it into a dynamic config, so it lives here; EAS_PROJECT_ID overrides it
// (for example to build under a different Expo account).
const EAS_PROJECT_ID = process.env.EAS_PROJECT_ID || 'c572b10d-eef7-403b-a7f7-292903a221a5'

const config: ExpoConfig = {
  name: 'QRGUARD',
  slug: 'qrguard',
  scheme: 'qrguard',
  version: '1.0.0',
  orientation: 'portrait',
  icon: './assets/icon.png',
  userInterfaceStyle: 'automatic',
  ios: { supportsTablet: true, bundleIdentifier: 'com.qrguard.app' },
  android: {
    package: 'com.qrguard.app',
    adaptiveIcon: {
      backgroundColor: '#E6F4FE',
      foregroundImage: './assets/android-icon-foreground.png',
      backgroundImage: './assets/android-icon-background.png',
      monochromeImage: './assets/android-icon-monochrome.png',
    },
    // Only what the app needs: the camera for scanning. No location, contacts or storage.
    permissions: ['android.permission.CAMERA'],
    blockedPermissions: ['android.permission.RECORD_AUDIO'],
    predictiveBackGestureEnabled: false,
  },
  web: { favicon: './assets/favicon.png' },
  plugins: [
    'expo-router',
    [
      'expo-camera',
      {
        cameraPermission: 'QRGUARD uses the camera only to scan QR codes. Nothing is recorded.',
        recordAudioAndroid: false,
      },
    ],
    [
      'expo-image-picker',
      {
        photosPermission: 'QRGUARD needs access to the photo you choose to check it for scams.',
        cameraPermission: false,
        microphonePermission: false,
      },
    ],
  ],
  experiments: { typedRoutes: true },
  extra: { eas: { projectId: EAS_PROJECT_ID } },
}

export default config
