import type { ExpoConfig } from 'expo/config'

// Only EXPO_PUBLIC_* values reach the app bundle, and they are public: never put secrets there.
const config: ExpoConfig = {
  name: 'QRGUARD',
  slug: 'qrguard',
  scheme: 'qrguard',
  version: '0.1.0',
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
}

export default config
