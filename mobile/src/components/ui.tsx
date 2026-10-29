import type { ReactNode } from 'react'
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View, type StyleProp, type ViewStyle } from 'react-native'
import { SafeAreaView } from 'react-native-safe-area-context'
import { colors, MIN_TOUCH, fonts } from '../constants/theme'
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
      {loading ? <ActivityIndicator color={variant === 'secondary' ? colors.brand : colors.onBrand} /> : null}
      <Text style={[styles.buttonText, variant === 'secondary' && styles.buttonTextSecondary]}>{label}</Text>
    </Pressable>
  )
}

const HINTS: Record<string, string> = {
  NETWORK_ERROR:
    'Check that the phone is online. If it is, the free QRGUARD server may be waking up: this can take up to a minute, then try again.',
  UPLOAD_FAILED:
    'This usually happens on a slow or unstable connection. Try again on Wi-Fi, or crop the image to the part that matters.',
  TIMEOUT: 'The server may be waking up or busy. Please try again.',
  SERVER_UNAVAILABLE: 'Please try again in a minute.',
  RATE_LIMITED: 'You have made many checks in a short time. Please wait a minute.',
  NO_TEXT_FOUND: 'Choose a screenshot where the message text is clearly visible, or a sharp photo of a QR code.',
  NO_QR_FOUND: 'Make sure the QR code is sharp, fully visible and not too small.',
  OCR_FAILED: 'Choose a sharper screenshot, or crop it to the message.',
  OCR_BUSY: 'Several images are being checked right now. Please try again in a moment.',
  OCR_UNAVAILABLE: 'Text recognition is not available on the server right now. QR codes can still be scanned with the camera.',
  FILE_TOO_LARGE: 'Choose a smaller image or crop it.',
  PAYLOAD_TOO_LARGE: 'Choose a smaller image or crop it.',
  IMAGE_TOO_LARGE: 'Choose a smaller image or crop it.',
  IMAGE_TOO_SMALL: 'The image is too small to read. Choose a larger screenshot.',
  UNSUPPORTED_MEDIA_TYPE: 'Choose a PNG, JPEG or WEBP image.',
  UNPROCESSABLE_IMAGE: 'The image file could not be read. Take a new screenshot and try again.',
  INCOMPLETE_URL: 'Type the full address, for example offer.com or https://www.example.in.',
  INVALID_URL: 'Check the link for typing mistakes.',
  AUTH_REQUIRED: 'Please sign in again in the Account tab.',
  INVALID_TOKEN: 'Sign out and sign in again in the Account tab.',
}

/** Problems worth retrying unchanged: the connection or the server, not the input. */
const RETRYABLE = new Set(['NETWORK_ERROR', 'UPLOAD_FAILED', 'TIMEOUT', 'SERVER_UNAVAILABLE', 'OCR_BUSY', 'HTTP_ERROR'])

export function ErrorBanner({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  return (
    <View style={styles.error} accessibilityRole="alert" testID="error-banner">
      <Text style={styles.errorTitle}>Could not complete the check</Text>
      <Text style={styles.errorText}>{error.message}</Text>
      {HINTS[error.code] ? <Text style={styles.errorText}>{HINTS[error.code]}</Text> : null}
      {error.requestId ? <Text style={styles.small}>Request ID: {error.requestId}</Text> : null}
      {onRetry && RETRYABLE.has(error.code) ? <ActionButton label="Try again" variant="secondary" onPress={onRetry} /> : null}
    </View>
  )
}

export const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: colors.background },
  content: { padding: 16, gap: 16, paddingBottom: 48 },
  title: { fontFamily: fonts.display, fontSize: 26, fontWeight: '700', color: colors.text },
  intro: { fontFamily: fonts.sans, fontSize: 16, color: colors.muted, lineHeight: 22 },
  card: { backgroundColor: colors.card, borderRadius: 16, padding: 16, gap: 12, borderWidth: 1, borderColor: colors.border },
  label: { fontFamily: fonts.sans, fontSize: 16, fontWeight: '600', color: colors.text },
  input: {
    minHeight: MIN_TOUCH,
    borderWidth: 1,
    borderColor: colors.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontFamily: fonts.sans,
    fontSize: 16,
    color: colors.text,
    backgroundColor: colors.card2,
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
  buttonSecondary: { backgroundColor: 'transparent', borderWidth: 1, borderColor: colors.brand },
  buttonDanger: { backgroundColor: colors.danger },
  buttonDisabled: { opacity: 0.5 },
  buttonPressed: { opacity: 0.8 },
  buttonText: { fontFamily: fonts.sans, color: colors.onBrand, fontSize: 16, fontWeight: '700' },
  buttonTextSecondary: { fontFamily: fonts.sans, color: colors.brand },
  error: { backgroundColor: '#2d1614', borderColor: '#7a2e27', borderWidth: 1, borderRadius: 12, padding: 12, gap: 4 },
  errorTitle: { fontFamily: fonts.sans, fontWeight: '700', color: colors.danger },
  errorText: { fontFamily: fonts.sans, color: colors.text },
  small: { fontFamily: fonts.sans, fontSize: 12, color: colors.muted },
  body: { fontFamily: fonts.sans, fontSize: 15, color: colors.text, lineHeight: 21 },
  mono: { fontFamily: fonts.mono, fontSize: 13, color: colors.text },
})
