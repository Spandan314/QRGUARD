import { useRouter, type Href } from 'expo-router'
import { Pressable, StyleSheet, Text, View } from 'react-native'
import { BackendStatus } from '../../components/BackendStatus'
import { Screen } from '../../components/ui'
import { colors, MIN_TOUCH } from '../../constants/theme'

const ACTIONS: { href: Href; icon: string; title: string; text: string }[] = [
  { href: '/scan/camera', icon: '📷', title: 'Scan a QR code', text: 'Check a QR code before you pay or open it.' },
  { href: '/check/url', icon: '🔗', title: 'Check a link', text: 'Look-alike domains, hidden redirects, known phishing.' },
  { href: '/check/message', icon: '💬', title: 'Check a message', text: 'Fake KYC, OTP requests, job, prize and UPI scams.' },
  { href: '/check/screenshot', icon: '📱', title: 'Check a screenshot', text: 'Reads the text and QR codes in a screenshot.' },
  { href: '/scan/image', icon: '🖼️', title: 'QR code from a photo', text: 'Check a QR code saved in your gallery.' },
]

export default function Home() {
  const router = useRouter()
  return (
    <Screen>
      <Text style={styles.heading}>Is it a scam? Check before you click, pay or scan.</Text>
      <BackendStatus />
      {ACTIONS.map((action) => (
        <Pressable
          key={String(action.href)}
          accessibilityRole="button"
          accessibilityLabel={action.title}
          onPress={() => router.push(action.href)}
          style={({ pressed }) => [styles.card, pressed && { opacity: 0.8 }]}
        >
          <Text style={styles.icon}>{action.icon}</Text>
          <View style={{ flex: 1 }}>
            <Text style={styles.title}>{action.title}</Text>
            <Text style={styles.text}>{action.text}</Text>
          </View>
        </Pressable>
      ))}
      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Make a QR code (utility)"
        onPress={() => router.push('/generate')}
        style={[styles.card, styles.utility]}
      >
        <Text style={styles.icon}>🔳</Text>
        <View style={{ flex: 1 }}>
          <Text style={styles.utilityLabel}>UTILITY</Text>
          <Text style={styles.title}>Make a QR code</Text>
          <Text style={styles.text}>Created on your phone; nothing is sent to QRGUARD.</Text>
        </View>
      </Pressable>
    </Screen>
  )
}

const styles = StyleSheet.create({
  heading: { fontSize: 22, fontWeight: '700', color: colors.text },
  card: {
    minHeight: MIN_TOUCH,
    flexDirection: 'row',
    gap: 12,
    alignItems: 'center',
    backgroundColor: colors.card,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: '#e2e8f0',
  },
  utility: { backgroundColor: '#f8fafc', borderStyle: 'dashed', borderColor: colors.border },
  utilityLabel: { fontSize: 11, fontWeight: '700', color: colors.utility, letterSpacing: 0.5 },
  icon: { fontSize: 30 },
  title: { fontSize: 17, fontWeight: '700', color: colors.text },
  text: { color: colors.muted },
})
