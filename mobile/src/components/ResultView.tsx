import type { ReactNode } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import { colors, LEVEL_THEME } from '../constants/theme'
import type { AnalysisResult } from '../types/api'
import { CONFIDENCE_TEXT, PROVIDER_NAME, TI_STATUS_TEXT } from '../utils/format'
import { IndicatorList } from './IndicatorList'
import { OpenLinkGuard } from './OpenLinkGuard'
import { RiskBadge } from './RiskBadge'
import { ScoreGauge } from './ScoreGauge'
import { Card, styles as ui } from './ui'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card>
      <Text style={ui.label} accessibilityRole="header">
        {title}
      </Text>
      {children}
    </Card>
  )
}

/** The link the user might want to open: the checked URL or a web link inside a QR code. */
function openableTarget(result: AnalysisResult): string | null {
  const a = result.analysis
  if (a.qr?.content_type === 'url') return a.qr.decoded_content
  if (result.input_type === 'url' && a.normalized_url) return a.normalized_url
  return null
}

export function ResultView({ result }: { result: AnalysisResult }) {
  const theme = LEVEL_THEME[result.risk_level]
  const verified = result.verification.status === 'VERIFIED'
  const a = result.analysis
  const target = openableTarget(result)

  return (
    <View style={{ gap: 16 }} testID="result-view">
      <View style={[styles.banner, { backgroundColor: theme.background, borderColor: theme.bar }]}>
        <RiskBadge level={result.risk_level} large />
        <Text style={[styles.summary, { color: theme.foreground }]}>{result.summary}</Text>
        <Text style={{ color: theme.foreground }}>{CONFIDENCE_TEXT[result.confidence]}</Text>
      </View>

      <Card>
        <ScoreGauge score={result.risk_score} level={result.risk_level} />
        <View testID="verification" style={{ gap: 2 }}>
          <Text style={ui.label}>
            {verified ? '🔎 Verified' : '❔ Unverified'}
            {result.verification.source === 'threat_intelligence' ? ' by threat intelligence' : ''}
            {result.verification.source === 'trusted_domain_list' ? ' – recognised legitimate website' : ''}
          </Text>
          <Text style={ui.body}>{result.verification.message}</Text>
          {result.risk_level === 'SAFE' && !verified ? (
            <Text style={[ui.body, { fontWeight: '600' }]}>
              No warning signs were found, but this is not a guarantee that it is safe.
            </Text>
          ) : null}
        </View>
      </Card>

      {result.categories.length > 0 ? (
        <Section title="Possible scam type">
          <Text style={ui.body}>{result.categories.map((c) => c.label).join(' · ')}</Text>
        </Section>
      ) : null}

      <Section title="What you should do">
        <Text style={ui.body}>{result.recommendation}</Text>
      </Section>

      <Section title="Why this result">
        <IndicatorList indicators={result.indicators} />
      </Section>

      {a.qr ? (
        <Section title={`QR code content (${a.qr.content_type})`}>
          <Text style={ui.mono} selectable testID="qr-content">
            {a.qr.decoded_content}
          </Text>
          {Object.entries(a.qr.parsed).map(([key, value]) => (
            <Text key={key} style={ui.small}>
              {key.replaceAll('_', ' ')}: {value === null || value === undefined || value === '' ? '—' : String(value)}
            </Text>
          ))}
          {a.qr.content_type === 'upi' ? (
            <Text style={[ui.body, { fontWeight: '600' }]}>
              Scanning a UPI QR code always sends money. You never need to scan a code or enter your PIN to
              receive money.
            </Text>
          ) : null}
        </Section>
      ) : null}

      {a.ocr ? (
        <Section title="Text read from the image">
          <Text style={ui.body} selectable testID="ocr-text">
            {a.ocr.extracted_text}
          </Text>
          <Text style={ui.small}>
            OCR quality: {a.ocr.quality}. Compare with your screenshot: letters can be misread.
          </Text>
        </Section>
      ) : null}

      {a.links?.length ? (
        <Section title="Links found">
          {a.links.map((link, index) => (
            <Text key={`${link.url}-${index}`} style={ui.mono} selectable>
              {link.risk_level ? `${LEVEL_THEME[link.risk_level].icon} ` : ''}
              {link.url}
            </Text>
          ))}
        </Section>
      ) : null}

      {target ? (
        <Section title="The link">
          <Text style={ui.mono} selectable>
            {target}
          </Text>
          <OpenLinkGuard url={target} level={result.risk_level} />
        </Section>
      ) : null}

      <Section title="Threat-intelligence checks">
        {result.threat_intel.providers.map((p) => (
          <Text key={p.provider} style={ui.body}>
            {PROVIDER_NAME[p.provider] ?? p.provider}: {TI_STATUS_TEXT[p.status]}
            {p.detail ? ` (${p.detail})` : ''}
            {p.limited_coverage ? ' · demo list only' : ''}
          </Text>
        ))}
        <Text style={ui.small}>{result.threat_intel.note}</Text>
      </Section>

      <Text style={[ui.small, { textAlign: 'center' }]}>
        {result.disclaimer}
        {'\n'}Request ID: {result.request_id}
      </Text>
    </View>
  )
}

const styles = StyleSheet.create({
  banner: { borderRadius: 16, borderWidth: 1, padding: 16, gap: 8 },
  summary: { fontSize: 17, fontWeight: '600' },
  muted: { color: colors.muted },
})
