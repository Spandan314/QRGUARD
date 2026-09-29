import { StyleSheet, Text, View } from 'react-native'
import { LEVEL_THEME } from '../constants/theme'
import type { RiskLevel } from '../types/api'

/** Icon + word + colour, so the level never depends on colour alone. */
export function RiskBadge({ level, large = false }: { level: RiskLevel; large?: boolean }) {
  const theme = LEVEL_THEME[level]
  return (
    <View
      style={[styles.badge, { backgroundColor: theme.background, borderColor: theme.bar }, large && styles.large]}
      accessible
      accessibilityLabel={`Risk level ${level}`}
      testID="risk-badge"
    >
      <Text style={[styles.text, { color: theme.foreground }, large && styles.largeText]}>
        {theme.icon} {theme.label}
      </Text>
    </View>
  )
}

const styles = StyleSheet.create({
  badge: { alignSelf: 'flex-start', borderRadius: 999, borderWidth: 1, paddingHorizontal: 10, paddingVertical: 3 },
  large: { paddingHorizontal: 14, paddingVertical: 6 },
  text: { fontWeight: '700', fontSize: 13 },
  largeText: { fontSize: 20 },
})
