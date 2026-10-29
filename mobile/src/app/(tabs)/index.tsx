import { useRouter, type Href } from 'expo-router'
import { Pressable, StyleSheet, Text, View } from 'react-native'
import { BackendStatus } from '../../components/BackendStatus'
import { TabIcon, type TabIconName } from '../../components/TabIcon'
import { Screen } from '../../components/ui'
import { colors, MIN_TOUCH, fonts } from '../../constants/theme'

const ACTIONS: { href: Href; icon: TabIconName; title: string; text: string }[] = [
  { href: '/scan/camera', icon: 'scan', title: 'Scan a QR code', text: 'Check a QR code before you pay or open it.' },
  { href: '/check/url', icon: 'link', title: 'Check a link', text: 'Look-alike domains, hidden redirects, known phishing.' },
  { href: '/check/message', icon: 'message', title: 'Check a message', text: 'Fake KYC, OTP requests, job, prize and UPI scams.' },
  { href: '/check/image', icon: 'image', title: 'Choose image to check', text: 'A screenshot of a message or a photo of a QR code.' },
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
          <View style={styles.icon}>
            <TabIcon name={action.icon} color={colors.brand} size={24} />
          </View>
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
        <View style={styles.icon}>
          <TabIcon name="qr" color={colors.muted} size={24} />
        </View>
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
  heading: { fontFamily: fonts.display, fontSize: 22, fontWeight: '700', color: colors.text },
  card: {
    minHeight: MIN_TOUCH,
    flexDirection: 'row',
    gap: 12,
    alignItems: 'center',
    backgroundColor: colors.card,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: colors.border,
  },
  utility: { backgroundColor: colors.card2, borderStyle: 'dashed', borderColor: colors.border },
  utilityLabel: { fontFamily: fonts.sans, fontSize: 11, fontWeight: '700', color: colors.utility, letterSpacing: 0.5 },
  icon: {
    width: 44,
    height: 44,
    borderRadius: 11,
    borderWidth: 1,
    borderColor: colors.border,
    backgroundColor: colors.card2,
    alignItems: 'center',
    justifyContent: 'center',
  },
  title: { fontFamily: fonts.display, fontSize: 17, fontWeight: '700', color: colors.text },
  text: { fontFamily: fonts.sans, color: colors.muted },
})
