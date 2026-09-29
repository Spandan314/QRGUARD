import { StyleSheet, Text, View } from 'react-native'
import { colors, LEVEL_THEME } from '../constants/theme'
import type { RiskLevel } from '../types/api'

export function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const value = Math.max(0, Math.min(100, score))
  return (
    <View
      accessible
      accessibilityRole="progressbar"
      accessibilityLabel="Risk score"
      accessibilityValue={{ min: 0, max: 100, now: value, text: `${value} out of 100, ${level}` }}
      testID="score-gauge"
    >
      <View style={styles.row}>
        <Text style={styles.label}>Risk score</Text>
        <Text style={styles.score}>
          {value}
          <Text style={styles.max}> / 100</Text>
        </Text>
      </View>
      <View style={styles.track}>
        <View style={[styles.fill, { width: `${value}%`, backgroundColor: LEVEL_THEME[level].bar }]} />
      </View>
      <View style={styles.row}>
        <Text style={styles.scale}>0 Safe</Text>
        <Text style={styles.scale}>30 Suspicious</Text>
        <Text style={styles.scale}>60 Malicious</Text>
      </View>
    </View>
  )
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'baseline' },
  label: { fontWeight: '600', color: colors.text },
  score: { fontSize: 26, fontWeight: '700', color: colors.text },
  max: { fontSize: 14, color: colors.muted, fontWeight: '400' },
  track: { height: 12, borderRadius: 6, backgroundColor: '#e2e8f0', overflow: 'hidden', marginVertical: 6 },
  fill: { height: '100%' },
  scale: { fontSize: 11, color: colors.muted },
})
