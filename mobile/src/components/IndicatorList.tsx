import { StyleSheet, Text, View } from 'react-native'
import { colors } from '../constants/theme'
import type { EvidenceSource, Indicator } from '../types/api'
import { evidenceSource, formatPoints, SEVERITY_ORDER, SOURCE_LABEL, SOURCE_ORDER } from '../utils/format'
import { styles as ui } from './ui'

/** Why the score is what it is: indicators grouped by where the evidence came from. */
export function IndicatorList({ indicators }: { indicators: Indicator[] }) {
  if (indicators.length === 0) return <Text style={ui.body}>No warning signs were found.</Text>
  const groups = new Map<EvidenceSource, Indicator[]>()
  for (const indicator of indicators) {
    const key = evidenceSource(indicator)
    groups.set(key, [...(groups.get(key) ?? []), indicator])
  }
  return (
    <View style={{ gap: 12 }}>
      {SOURCE_ORDER.filter((source) => groups.has(source)).map((source) => (
        <View key={source} style={{ gap: 8 }}>
          <Text style={styles.group}>{SOURCE_LABEL[source].toUpperCase()}</Text>
          {[...(groups.get(source) ?? [])]
            .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
            .map((indicator, index) => (
              <View key={`${indicator.id}-${index}`} style={styles.item} testID="indicator">
                <View style={styles.header}>
                  <Text style={styles.title}>{indicator.title}</Text>
                  <Text style={styles.points}>{formatPoints(indicator.score_contribution)} pts</Text>
                </View>
                <Text style={styles.severity}>{indicator.severity.toUpperCase()}</Text>
                <Text style={ui.body}>{indicator.message}</Text>
                {indicator.evidence ? <Text style={ui.small}>Evidence: {indicator.evidence}</Text> : null}
              </View>
            ))}
        </View>
      ))}
    </View>
  )
}

const styles = StyleSheet.create({
  group: { fontSize: 12, fontWeight: '700', color: colors.muted, letterSpacing: 0.5 },
  item: { borderWidth: 1, borderColor: '#e2e8f0', borderRadius: 10, padding: 10, gap: 4 },
  header: { flexDirection: 'row', justifyContent: 'space-between', gap: 8 },
  title: { flex: 1, fontWeight: '600', fontSize: 15, color: colors.text },
  points: { fontFamily: 'monospace', color: colors.muted },
  severity: { fontSize: 11, fontWeight: '700', color: colors.muted },
})
