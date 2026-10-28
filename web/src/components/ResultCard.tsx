import type { AnalysisResult, CheckStatus } from '../types/api'
import { CONFIDENCE_TEXT, VERDICT_STYLE } from '../utils/format'
import { verdictOf, verificationNote } from '../utils/verdict'
import { AnalysisDetailsView } from './AnalysisDetails'
import { Icon, type IconName } from './Icon'
import { IndicatorList } from './IndicatorList'
import { OpenCheckedLink } from './OpenCheckedLink'
import { ReportForm } from './ReportForm'
import { RiskBadge } from './RiskBadge'
import { ScoreGauge } from './ScoreGauge'
import { ThreatIntelStatus } from './ThreatIntelStatus'

const sectionTitle = 'mb-2 text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400'

function VerificationNote({ result }: { result: AnalysisResult }) {
  const note = verificationNote(result, verdictOf(result))
  return (
    <div className="flex gap-3 text-sm" data-testid="verification">
      <Icon
        name={note.verified ? 'shield-check' : 'help'}
        className={`mt-0.5 h-5 w-5 ${note.verified ? 'text-teal-700 dark:text-teal-400' : 'text-slate-400'}`}
      />
      <div>
        <p className="font-medium">{note.heading}</p>
        {note.message ? <p className="mt-0.5 text-slate-600 dark:text-slate-300">{note.message}</p> : null}
      </div>
    </div>
  )
}

const CHECK_ICON: Record<CheckStatus, { icon: IconName; tone: string }> = {
  completed: { icon: 'check', tone: 'text-teal-700 dark:text-teal-400' },
  limited: { icon: 'half-circle', tone: 'text-amber-600 dark:text-amber-400' },
  not_run: { icon: 'minus', tone: 'text-slate-400' },
  incomplete: { icon: 'alert-triangle', tone: 'text-amber-600 dark:text-amber-400' },
  unavailable: { icon: 'alert-triangle', tone: 'text-amber-600 dark:text-amber-400' },
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
      <ul className="divide-y divide-slate-100 rounded-md border border-slate-200 text-sm dark:divide-slate-800 dark:border-slate-700">
        {result.checks.map((check) => (
          <li key={check.id} className="flex items-start gap-2.5 px-3 py-2" data-testid={`check-${check.id}`}>
            <Icon name={CHECK_ICON[check.status].icon} className={`mt-0.5 h-4 w-4 ${CHECK_ICON[check.status].tone}`} />
            <span>
              {check.label}: <span className="font-medium">{CHECK_TEXT[check.status]}</span>
              {check.detail ? <span className="text-slate-500 dark:text-slate-400"> ({check.detail})</span> : null}
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
    <p className="text-sm text-slate-600 dark:text-slate-300" data-testid="history-notice">
      {result.history.saved
        ? 'Saved to your history (verdict only).'
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

export function ResultCard({ result }: { result: AnalysisResult }) {
  const verdict = verdictOf(result)
  const style = VERDICT_STYLE[verdict.label]
  const target = openableTarget(result)
  const a = result.analysis
  const finalUrl =
    result.input_type === 'url' && a.redirects?.final_url && a.redirects.final_url !== a.normalized_url
      ? a.redirects.final_url
      : null
  return (
    <article
      className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-700 dark:bg-slate-900"
      aria-live="polite"
      aria-label="Analysis result"
    >
      <header className={`grid gap-5 border-l-4 p-5 sm:grid-cols-[1fr_15rem] ${style.accent.split(' ')[0]}`}>
        <div className="flex gap-4">
          <Icon name={style.icon} className={`mt-1 h-8 w-8 ${style.accent.split(' ').slice(1).join(' ')}`} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge verdict={verdict.label} size="lg" />
              <span className="text-xs text-slate-500 dark:text-slate-400">{CONFIDENCE_TEXT[result.confidence]}</span>
            </div>
            <p className="mt-2 text-xl font-semibold tracking-tight" data-testid="verdict-title">
              {verdict.title}
            </p>
            <p className="mt-1 text-slate-600 dark:text-slate-300">{result.summary}</p>
          </div>
        </div>
        <div className="self-center">
          <ScoreGauge score={result.risk_score} level={result.risk_level} />
        </div>
      </header>

      <section
        className="flex gap-3 border-y border-teal-100 bg-teal-50/60 px-5 py-4 dark:border-teal-900 dark:bg-teal-950/40"
        data-testid="recommendation"
      >
        <Icon name="arrow-right" className="mt-0.5 h-5 w-5 text-teal-700 dark:text-teal-400" />
        <div>
          <h3 className="font-semibold">What you should do</h3>
          <p className="mt-1 text-slate-700 dark:text-slate-200">{result.recommendation}</p>
        </div>
      </section>

      <div className="space-y-6 p-5">
        <div className="grid gap-5 md:grid-cols-2">
          <section>
            <h3 className={sectionTitle}>Verification</h3>
            <VerificationNote result={result} />
            {result.categories.length > 0 ? (
              <div className="mt-4">
                <h3 className={sectionTitle}>Possible scam type</h3>
                <ul className="flex flex-wrap gap-1.5">
                  {result.categories.map((category) => (
                    <li key={category.id} className="rounded-md bg-slate-100 px-2 py-1 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                      {category.label}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>
          <ChecksList result={result} />
        </div>

        <section>
          <h3 className={sectionTitle}>Why this result</h3>
          <IndicatorList indicators={result.indicators} />
        </section>

        {target ? <OpenCheckedLink url={target} verdict={verdict.label} finalUrl={finalUrl} /> : null}

        <section>
          <h3 className={sectionTitle}>Threat-intelligence checks</h3>
          <ThreatIntelStatus threatIntel={result.threat_intel} />
        </section>

        <AnalysisDetailsView result={result} />

        <HistoryNotice result={result} />
        <ReportForm scanId={result.history?.scan_id} />
      </div>

      <footer className="border-t border-slate-200 bg-slate-50 px-5 py-3 text-xs text-slate-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-400">
        <p>{result.disclaimer}</p>
        <p className="mt-1">
          Request ID: <span className="font-mono">{result.request_id}</span>
          {result.engine_version ? ` · engine ${result.engine_version}` : ''}
        </p>
      </footer>
    </article>
  )
}
