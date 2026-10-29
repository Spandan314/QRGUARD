import type { ReactNode } from 'react'
import type { AnalysisResult, CheckStatus } from '../types/api'
import { CONFIDENCE_TEXT, VERDICT_STYLE } from '../utils/format'
import { claimsVsReality, linkXray, officialSite, redirectChain, scoreBreakdown, xrayNotes } from '../utils/result'
import { verdictOf, verificationNote } from '../utils/verdict'
import { AnalysisDetailsView } from './AnalysisDetails'
import { Icon, type IconName } from './Icon'
import { IndicatorList } from './IndicatorList'
import { OpenCheckedLink } from './OpenCheckedLink'
import { ReportForm } from './ReportForm'
import { RiskBadge } from './RiskBadge'
import { ScoreGauge } from './ScoreGauge'
import { ClaimsVsReality } from './result/ClaimsVsReality'
import { InspectionPass } from './result/InspectionPass'
import { LinkXray } from './result/LinkXray'
import { RedirectChain } from './result/RedirectChain'
import { ScoreBreakdown } from './result/ScoreBreakdown'
import { ThreatIntelStatus } from './ThreatIntelStatus'

const sectionTitle = 'label-mono mb-2 block font-mono'

function VerificationNote({ result }: { result: AnalysisResult }) {
  const note = verificationNote(result, verdictOf(result))
  return (
    <div className="flex gap-3 text-sm" data-testid="verification">
      <Icon
        name={note.verified ? 'shield-check' : 'help'}
        className={`mt-0.5 h-5 w-5 ${note.verified ? 'text-accent' : 'text-muted'}`}
      />
      <div>
        <p className="font-medium">{note.heading}</p>
        {note.message ? <p className="mt-0.5 text-muted">{note.message}</p> : null}
      </div>
    </div>
  )
}

const CHECK_ICON: Record<CheckStatus, { icon: IconName; tone: string }> = {
  completed: { icon: 'check', tone: 'text-accent' },
  limited: { icon: 'half-circle', tone: 'text-warn' },
  not_run: { icon: 'minus', tone: 'text-muted' },
  incomplete: { icon: 'alert-triangle', tone: 'text-warn' },
  unavailable: { icon: 'alert-triangle', tone: 'text-warn' },
}
const CHECK_TEXT: Record<CheckStatus, string> = {
  completed: 'done',
  limited: 'limited',
  not_run: 'not checked',
  incomplete: 'could not be completed',
  unavailable: 'unavailable',
}

function ChecksList({ result }: { result: AnalysisResult }) {
  if (!result.checks?.length) return null
  return (
    <section>
      <h3 className={sectionTitle}>What QRGUARD checked</h3>
      <ul className="divide-y divide-line rounded-panel border border-line text-sm">
        {result.checks.map((check) => (
          <li key={check.id} className="flex items-start gap-2.5 px-3 py-2" data-testid={`check-${check.id}`}>
            <Icon name={CHECK_ICON[check.status].icon} className={`mt-0.5 h-4 w-4 ${CHECK_ICON[check.status].tone}`} />
            <span>
              {check.label}: <span className="font-medium">{CHECK_TEXT[check.status]}</span>
              {check.detail ? <span className="text-muted"> ({check.detail})</span> : null}
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}

const HISTORY_REASON: Record<string, string> = {
  sign_in_required: 'Not saved: sign in to keep a history.',
  history_disabled: 'Not saved: saving is switched off in your account settings.',
  history_unavailable: 'Not saved: history is not available on this server.',
  history_error: 'Not saved: history is temporarily unavailable. Your result is still valid.',
}

function HistoryNotice({ result }: { result: AnalysisResult }) {
  if (!result.history) return null
  return (
    <p className="text-sm text-muted" data-testid="history-notice">
      {result.history.saved
        ? 'Saved to your history (only the result, not what you checked).'
        : (HISTORY_REASON[result.history.reason ?? ''] ?? 'Not saved.')}
    </p>
  )
}

/** The link the user may want to open: the checked URL, or a web link inside a QR code. */
function openableTarget(result: AnalysisResult): string | null {
  const a = result.analysis
  if (a.qr?.content_type === 'url') return a.qr.decoded_content
  if (result.input_type === 'url' && a.normalized_url) return a.normalized_url
  return null
}

const VERDICT_TONE: Record<string, string> = {
  SAFE: 'text-accent',
  UNVERIFIED: 'text-muted',
  SUSPICIOUS: 'text-warn',
  MALICIOUS: 'text-danger',
}

const panel = 'rounded-panel border border-line bg-panel p-5'

export function ResultCard({ result, actions }: { result: AnalysisResult; actions?: ReactNode }) {
  const verdict = verdictOf(result)
  const style = VERDICT_STYLE[verdict.label]
  const tone = VERDICT_TONE[verdict.label] ?? 'text-ink'
  const target = openableTarget(result)
  const a = result.analysis
  const finalUrl =
    result.input_type === 'url' && a.redirects?.final_url && a.redirects.final_url !== a.normalized_url
      ? a.redirects.final_url
      : null
  const claims = claimsVsReality(result, verdict.label)
  const xray = linkXray(result)
  const breakdown = scoreBreakdown(result)
  const chain = redirectChain(result)
  const official = officialSite(result)
  return (
    <article className="space-y-6" aria-live="polite" aria-label="Analysis result">
      <header className={`grid gap-6 rounded-panel-lg border border-l-4 border-line bg-panel p-5 sm:grid-cols-[1fr_auto] sm:p-7 ${style.accent.split(' ')[0]}`}>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge verdict={verdict.label} size="lg" />
            <span className="font-mono text-xs text-muted">{CONFIDENCE_TEXT[result.confidence]}</span>
          </div>
          <p className="mt-3 font-display text-2xl font-bold tracking-tight sm:text-4xl" data-testid="verdict-title">
            {verdict.title}
          </p>
          <p className="mt-2 max-w-2xl text-muted">{result.summary}</p>
        </div>
        <div className="sm:w-64 sm:self-center">
          <p className="flex items-baseline gap-2 sm:justify-end">
            <span className={`font-display text-6xl leading-none font-bold tabular-nums ${tone}`} data-testid="big-score">
              {result.risk_score}
            </span>
            <span className="text-muted">out of 100 risk</span>
          </p>
          <div className="mt-3">
            <ScoreGauge score={result.risk_score} level={result.risk_level} />
          </div>
        </div>
      </header>

      <section className="rounded-panel-lg border border-line bg-panel-2 p-5 sm:p-6" data-testid="recommendation">
        <h3 className="font-display text-lg font-semibold">What you should do</h3>
        <p className="mt-2 max-w-3xl">{result.recommendation}</p>
        <div className="mt-4 flex flex-wrap items-center gap-2">
          {official ? (
            <a
              href={official.url}
              target="_blank"
              rel="noopener noreferrer"
              referrerPolicy="no-referrer"
              className="inline-flex min-h-11 items-center gap-2 rounded-btn bg-accent px-5 text-sm font-semibold text-on-accent hover:opacity-90"
              data-testid="open-official-site"
            >
              Open the real site instead
              <span className="font-mono text-xs opacity-80">{official.domain}</span>
            </a>
          ) : null}
          {actions}
        </div>
        {official ? (
          <p className="mt-2 text-xs text-muted">We link to the official {official.brand} site we know, never to the one you scanned.</p>
        ) : null}
      </section>

      <InspectionPass key={result.request_id} result={result} />

      <ClaimsVsReality rows={claims} />
      <LinkXray parts={xray} notes={xrayNotes(result, xray, verdict.label)} />

      <div className="grid gap-5 lg:grid-cols-2">
        <ScoreBreakdown rows={breakdown.rows} total={breakdown.total} tone={tone} />
        <section aria-labelledby="sources-title" className={panel}>
          <h3 id="sources-title" className="font-display text-lg font-semibold">
            Scam databases
          </h3>
          <div className="mt-3">
            <ThreatIntelStatus threatIntel={result.threat_intel} />
          </div>
        </section>
      </div>

      <RedirectChain chain={chain} />

      <div className="grid gap-5 md:grid-cols-2">
        <section className={panel}>
          <h3 className={sectionTitle}>Confirmed?</h3>
          <VerificationNote result={result} />
          {result.categories.length > 0 ? (
            <div className="mt-4">
              <h3 className={sectionTitle}>Possible scam type</h3>
              <ul className="flex flex-wrap gap-1.5">
                {result.categories.map((category) => (
                  <li key={category.id} className="rounded-btn border border-line bg-panel-2 px-2 py-1 text-xs font-medium">
                    {category.label}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
        <div className={panel}>
          <ChecksList result={result} />
        </div>
      </div>

      <section className={panel}>
        <h3 className="font-display text-lg font-semibold">Why this result</h3>
        <div className="mt-3">
          <IndicatorList indicators={result.indicators} />
        </div>
      </section>

      {target ? <OpenCheckedLink url={target} verdict={verdict.label} finalUrl={finalUrl} /> : null}
      <AnalysisDetailsView result={result} />
      <HistoryNotice result={result} />
      <ReportForm scanId={result.history?.scan_id} />

      <footer className="border-t border-line pt-3 text-xs text-muted">
        <p>{result.disclaimer}</p>
        <p className="mt-1">
          Request ID: <span className="font-mono">{result.request_id}</span>
          {result.engine_version ? ` · engine ${result.engine_version}` : ''}
        </p>
      </footer>
    </article>
  )
}
