import type { ReactNode } from 'react'
import { StyleSheet, Text, View } from 'react-native'
import { colors, LEVEL_THEME, VERDICT_THEME, fonts } from '../constants/theme'
import type { AnalysisResult, CheckStatus, RiskLevel } from '../types/api'
import { CONFIDENCE_TEXT, PROVIDER_NAME } from '../utils/format'
import { providerState, providerSummary, type ProviderOutcome } from '../utils/providerStatus'
import { verdictOf, verificationNote } from '../utils/verdict'
import { IndicatorList } from './IndicatorList'
import { OpenLinkGuard } from './OpenLinkGuard'
import { ReportForm } from './ReportForm'
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

const CHECK_ICON: Record<CheckStatus, string> = {
  completed: '✔',
  limited: '◐',
  not_run: '–',
  incomplete: '⚠️',
  unavailable: '⚠️',
}

const CHECK_STATUS_TEXT: Record<CheckStatus, string> = {
  completed: 'done',
  limited: 'limited',
  not_run: 'not checked',
  incomplete: 'could not be completed',
  unavailable: 'unavailable',
}

/** A per-link score band. A clean link is shown neutrally: no warning signs is not "safe". */
function linkIcon(level: RiskLevel): string {
  return level === 'SAFE' ? '❔' : LEVEL_THEME[level].icon
}

const OUTCOME_ICON: Record<ProviderOutcome, string> = { flagged: '⛔', checked: '✓', not_checked: '⚠', not_configured: '–' }
const OUTCOME_COLOR: Record<ProviderOutcome, string> = {
  flagged: colors.danger,
  checked: colors.text,
  not_checked: colors.warn, // a warning, not a result
  not_configured: colors.muted,
}

export function ResultView({ result }: { result: AnalysisResult }) {
  const verdict = verdictOf(result)
  const theme = VERDICT_THEME[verdict.label]
  const note = verificationNote(result, verdict)
  const a = result.analysis
  const target = openableTarget(result)
  const redirects = a.redirects
  const finalUrl =
    result.input_type === 'url' && redirects?.final_url && redirects.final_url !== a.normalized_url
      ? redirects.final_url
      : null

  return (
    <View style={{ gap: 16 }} testID="result-view">
      <View style={[styles.banner, { backgroundColor: theme.background, borderColor: theme.bar }]}>
        <RiskBadge verdict={verdict.label} large />
        <Text style={[styles.title, { color: theme.foreground }]} testID="verdict-title">
          {verdict.title}
        </Text>
        <Text style={[styles.summary, { color: theme.foreground }]}>{result.summary}</Text>
        <Text style={{ fontFamily: fonts.sans, color: theme.foreground }}>{CONFIDENCE_TEXT[result.confidence]}</Text>
      </View>

      <Section title="What you should do">
        <Text style={ui.body}>{result.recommendation}</Text>
      </Section>

      <Card>
        <ScoreGauge score={result.risk_score} level={result.risk_level} />
        <View testID="verification" style={{ gap: 2 }}>
          <Text style={ui.label}>{note.heading}</Text>
          {note.message ? <Text style={ui.body}>{note.message}</Text> : null}
        </View>
      </Card>

      {result.checks?.length ? (
        <Section title="What QRGUARD checked">
          {result.checks.map((check) => (
            <Text key={check.id} style={ui.body} testID={`check-${check.id}`}>
              {CHECK_ICON[check.status]} {check.label}: {CHECK_STATUS_TEXT[check.status]}
              {check.detail ? ` (${check.detail})` : ''}
            </Text>
          ))}
        </Section>
      ) : null}

      {finalUrl ? (
        <Section title="Where this link leads">
          <Text style={ui.body}>
            When opened, this link forwards to a different address. QRGUARD checked both.
          </Text>
          <Text style={ui.mono} selectable testID="final-url">
            {finalUrl}
          </Text>
        </Section>
      ) : null}

      {result.categories.length > 0 ? (
        <Section title="Possible scam type">
          <Text style={ui.body}>{result.categories.map((c) => c.label).join(' · ')}</Text>
        </Section>
      ) : null}

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
              {link.risk_level ? `${linkIcon(link.risk_level)} ` : ''}
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
          <OpenLinkGuard url={target} verdict={verdict.label} finalUrl={finalUrl} />
        </Section>
      ) : null}

      <Section title="Threat-intelligence checks">
        {result.threat_intel.providers.length ? (
          <Text style={ui.label} testID="ti-summary">
            {providerSummary(result.threat_intel)}
          </Text>
        ) : null}
        {result.threat_intel.providers.map((p) => {
          const state = providerState(p)
          return (
            <Text key={p.provider} style={[ui.body, { color: OUTCOME_COLOR[state.outcome] }]}>
              {OUTCOME_ICON[state.outcome]} {PROVIDER_NAME[p.provider] ?? p.provider}: {state.label}
            </Text>
          )
        })}
        <Text style={ui.small}>{result.threat_intel.note}</Text>
      </Section>

      {result.history ? (
        <Text style={ui.small} testID="history-notice">
          {result.history.saved
            ? '💾 Saved to your history (verdict only).'
            : (HISTORY_REASON[result.history.reason ?? ''] ?? 'Not saved.')}
        </Text>
      ) : null}
      <ReportForm scanId={result.history?.scan_id} />

      <Text style={[ui.small, { textAlign: 'center' }]}>
        {result.disclaimer}
        {'\n'}Request ID: {result.request_id}
      </Text>
    </View>
  )
}

const HISTORY_REASON: Record<string, string> = {
  sign_in_required: 'Not saved: sign in to keep a history.',
  history_disabled: 'Not saved: saving is switched off in your account.',
  history_unavailable: 'Not saved: history is not available on this server.',
  history_error: 'Not saved: history is temporarily unavailable. Your result is still valid.',
}

const styles = StyleSheet.create({
  banner: { borderRadius: 16, borderWidth: 1, padding: 16, gap: 8 },
  title: { fontFamily: fonts.display, fontSize: 19, fontWeight: '700' },
  summary: { fontFamily: fonts.sans, fontSize: 16, fontWeight: '500' },
  muted: { fontFamily: fonts.sans, color: colors.muted },
})
