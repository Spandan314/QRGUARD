import { Stack } from 'expo-router'
import { StatusBar } from 'expo-status-bar'
import { SafeAreaProvider } from 'react-native-safe-area-context'
import { colors, fonts } from '../constants/theme'
import { AuthProvider } from '../context/AuthContext'
import { ResultProvider } from '../context/ResultContext'
import { ThemeProvider, useTheme } from '../context/ThemeContext'

export default function RootLayout() {
  return (
    <SafeAreaProvider>
      <AuthProvider>
      <ResultProvider>
      <ThemeProvider>
        <ThemedStack />
      </ThemeProvider>
      </ResultProvider>
      </AuthProvider>
    </SafeAreaProvider>
  )
}

function ThemedStatusBar() {
  const { theme } = useTheme()
  return <StatusBar style={theme === 'light' ? 'dark' : 'light'} />
}

/** Rendered inside ThemeProvider, so the header colors follow the theme. */
function ThemedStack() {
  return (
    <>
      <ThemedStatusBar />
      <Stack
        screenOptions={{
          headerTintColor: colors.brand,
          headerStyle: { backgroundColor: colors.card },
          headerShadowVisible: false,
          headerTitleStyle: { fontFamily: fonts.display, fontWeight: '700', color: colors.text },
          contentStyle: { backgroundColor: colors.background },
        }}
      >
        <Stack.Screen name="(tabs)" options={{ headerShown: false }} />
        <Stack.Screen name="scan/camera" options={{ title: 'Scan a QR code' }} />
        <Stack.Screen name="check/url" options={{ title: 'Check a link' }} />
        <Stack.Screen name="check/message" options={{ title: 'Check a message' }} />
        <Stack.Screen name="check/image" options={{ title: 'Check an image' }} />
        <Stack.Screen name="generate" options={{ title: 'Make a QR code' }} />
        <Stack.Screen name="result" options={{ title: 'Result' }} />
      </Stack>
    </>
  )
}
