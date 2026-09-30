import type { ReactNode } from 'react'
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View, type StyleProp, type ViewStyle } from 'react-native'
import { SafeAreaView } from 'react-native-safe-area-context'
import { colors, MIN_TOUCH } from '../constants/theme'
import type { ApiError } from '../services/api'

export function Screen({ children, title, intro }: { children: ReactNode; title?: string; intro?: string }) {
  return (
    <SafeAreaView style={styles.safe} edges={['bottom', 'left', 'right']}>
      <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
        {title ? (
          <Text style={styles.title} accessibilityRole="header">
            {title}
          </Text>
        ) : null}
        {intro ? <Text style={styles.intro}>{intro}</Text> : null}
        {children}
      </ScrollView>
    </SafeAreaView>
  )
}

export function Card({ children, style }: { children: ReactNode; style?: StyleProp<ViewStyle> }) {
  return <View style={[styles.card, style]}>{children}</View>
}

export function ActionButton({
  label,
  onPress,
  disabled = false,
  loading = false,
  variant = 'primary',
}: {
  label: string
  onPress: () => void
  disabled?: boolean
  loading?: boolean
  variant?: 'primary' | 'secondary' | 'danger'
}) {
  const inactive = disabled || loading
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ disabled: inactive, busy: loading }}
      disabled={inactive}
      onPress={onPress}
      style={({ pressed }) => [
        styles.button,
        variant === 'secondary' && styles.buttonSecondary,
        variant === 'danger' && styles.buttonDanger,
        inactive && styles.buttonDisabled,
        pressed && styles.buttonPressed,
      ]}
    >
      {loading ? <ActivityIndicator color="#fff" /> : null}
      <Text style={[styles.buttonText, variant === 'secondary' && styles.buttonTextSecondary]}>{label}</Text>
    </Pressable>
  )
}

const HINTS: Record<string, string> = {
  NETWORK_ERROR: 'The server may be starting up (this can take up to a minute). Check that the phone is online.',
  RATE_LIMITED: 'You have made many checks in a short time. Please wait a minute.',
  NO_TEXT_FOUND: 'Try a sharper screenshot where the message text is clearly visible.',
  NO_QR_FOUND: 'Make sure the QR code is sharp, fully visible and not too small.',
  OCR_UNAVAILABLE: 'Text recognition is not available on the server right now.',
}

export function ErrorBanner({ error }: { error: ApiError }) {
  return (
    <View style={styles.error} accessibilityRole="alert" testID="error-banner">
      <Text style={styles.errorTitle}>Could not complete the check</Text>
      <Text style={styles.errorText}>{error.message}</Text>
      {HINTS[error.code] ? <Text style={styles.errorText}>{HINTS[error.code]}</Text> : null}
      {error.requestId ? <Text style={styles.small}>Request ID: {error.requestId}</Text> : null}
    </View>
  )
}

export const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  content: { padding: 16, gap: 16, paddingBottom: 48 },
  title: { fontSize: 26, fontWeight: '700', color: colors.text },
  intro: { fontSize: 16, color: colors.muted, lineHeight: 22 },
  card: { backgroundColor: colors.card, borderRadius: 16, padding: 16, gap: 12, borderWidth: 1, borderColor: '#e2e8f0' },
  label: { fontSize: 16, fontWeight: '600', color: colors.text },
  input: {
    minHeight: MIN_TOUCH,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
    color: colors.text,
    backgroundColor: '#fff',
  },
  button: {
    minHeight: MIN_TOUCH,
    borderRadius: 10,
    backgroundColor: colors.brand,
    paddingHorizontal: 16,
    flexDirection: 'row',
    gap: 8,
    alignItems: 'center',
    justifyContent: 'center',
  },
  buttonSecondary: { backgroundColor: '#fff', borderWidth: 1, borderColor: colors.brand },
  buttonDanger: { backgroundColor: colors.danger },
  buttonDisabled: { opacity: 0.5 },
  buttonPressed: { opacity: 0.8 },
  buttonText: { color: '#fff', fontSize: 16, fontWeight: '700' },
  buttonTextSecondary: { color: colors.brand },
  error: { backgroundColor: '#fef2f2', borderColor: '#fca5a5', borderWidth: 1, borderRadius: 12, padding: 12, gap: 4 },
  errorTitle: { fontWeight: '700', color: '#7f1d1d' },
  errorText: { color: '#7f1d1d' },
  small: { fontSize: 12, color: colors.muted },
  body: { fontSize: 15, color: colors.text, lineHeight: 21 },
  mono: { fontFamily: 'monospace', fontSize: 13, color: colors.text },
})
