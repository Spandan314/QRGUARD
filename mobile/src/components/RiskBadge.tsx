import { StyleSheet, Text, View } from 'react-native'
import { VERDICT_THEME, fonts, themedStyles } from '../constants/theme'
import type { VerdictLabel } from '../types/api'

/** Icon + word + colour, so the verdict never depends on colour alone. */
export function RiskBadge({ verdict, large = false }: { verdict: VerdictLabel; large?: boolean }) {
  const theme = VERDICT_THEME[verdict]
  return (
    <View
      style={[styles.badge, { backgroundColor: theme.background, borderColor: theme.bar }, large && styles.large]}
      accessible
      accessibilityLabel={`Result: ${theme.label}`}
      testID="risk-badge"
    >
      <Text style={[styles.text, { color: theme.foreground }, large && styles.largeText]}>
        {theme.icon} {theme.label}
      </Text>
    </View>
  )
}

const styles = themedStyles(() =>
  StyleSheet.create({
  badge: { alignSelf: 'flex-start', borderRadius: 999, borderWidth: 1, paddingHorizontal: 10, paddingVertical: 3 },
  large: { paddingHorizontal: 14, paddingVertical: 6 },
  text: { fontFamily: fonts.sans, fontWeight: '700', fontSize: 13 },
  largeText: { fontSize: 20 },
}),
)
