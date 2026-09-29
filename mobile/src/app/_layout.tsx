import { Stack } from 'expo-router'
import { StatusBar } from 'expo-status-bar'
import { SafeAreaProvider } from 'react-native-safe-area-context'
import { colors } from '../constants/theme'
import { AuthProvider } from '../context/AuthContext'
import { ResultProvider } from '../context/ResultContext'

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <AuthProvider>
      <ResultProvider>
        <StatusBar style="auto" />
        <Stack
          screenOptions={{
            headerTintColor: colors.brand,
            headerTitleStyle: { fontWeight: '700' },
            contentStyle: { backgroundColor: colors.background },
          }}
        >
          <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
          <Stack.Screen name="scan/camera" options={{ title: 'Scan a QR code' }} />
          <Stack.Screen name="scan/image" options={{ title: 'QR code from a photo' }} />
          <Stack.Screen name="check/url" options={{ title: 'Check a link' }} />
          <Stack.Screen name="check/message" options={{ title: 'Check a message' }} />
          <Stack.Screen name="check/screenshot" options={{ title: 'Check a screenshot' }} />
          <Stack.Screen name="generate" options={{ title: 'Make a QR code' }} />
          <Stack.Screen name="result" options={{ title: 'Result' }} />
        </Stack>
      </ResultProvider>
      </AuthProvider>
    </SafeAreaProvider>
  )
}
