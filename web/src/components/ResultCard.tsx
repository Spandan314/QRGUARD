import type { AnalysisResult } from '../types/api'
import { CONFIDENCE_TEXT, LEVEL_STYLE } from '../utils/format'
import { AnalysisDetailsView } from './AnalysisDetails'
import { IndicatorList } from './IndicatorList'
import { ReportForm } from './ReportForm'
import { RiskBadge } from './RiskBadge'
import { ScoreGauge } from './ScoreGauge'
import { ThreatIntelStatus } from './ThreatIntelStatus'

function VerificationNote({ result }: { result: AnalysisResult }) {
  const { verification, risk_level: level } = result
  const verified = verification.status === 'VERIFIED'
  return (
    <div
      className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-700"
      data-testid="verification"
    >
      <p className="font-semibold">
        {verified ? '🔎 Verified' : '❔ Unverified'}
        {verification.source === 'threat_intelligence' ? ' by threat intelligence' : ''}
        {verification.source === 'trusted_domain_list' ? ' – recognised legitimate website' : ''}
      </p>
      <p className="mt-1 text-slate-700 dark:text-slate-300">{verification.message}</p>
      {level === 'SAFE' && !verified ? (
        <p className="mt-1 font-medium text-slate-800 dark:text-slate-200">
          No warning signs were found, but this is not a guarantee that it is safe.
        </p>
      ) : null}
    </div>
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
        ? '💾 Saved to your history (verdict only).'
        : (HISTORY_REASON[result.history.reason ?? ''] ?? 'Not saved.')}
    </p>
  )
}

export function ResultCard({ result }: { result: AnalysisResult }) {
  const level = LEVEL_STYLE[result.risk_level]
  return (
    <article
      className="space-y-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900"
      aria-live="polite"
      aria-label="Analysis result"
    >
      <header className={`rounded-xl p-4 ring-1 ring-inset ${level.classes}`}>
        <div className="flex flex-wrap items-center gap-3">
          <RiskBadge level={result.risk_level} size="lg" />
          <span className="text-sm">{CONFIDENCE_TEXT[result.confidence]}</span>
        </div>
        <p className="mt-3 text-base font-medium">{result.summary}</p>
      </header>

      <ScoreGauge score={result.risk_score} level={result.risk_level} />
      <VerificationNote result={result} />

      {result.categories.length > 0 ? (
        <section>
          <h3 className="mb-2 font-semibold">Possible scam type</h3>
          <ul className="flex flex-wrap gap-2">
            {result.categories.map((category) => (
              <li key={category.id} className="rounded-full bg-slate-100 px-3 py-1 text-sm dark:bg-slate-800">
                {category.label}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="rounded-xl bg-slate-50 p-4 dark:bg-slate-800">
        <h3 className="mb-1 font-semibold">What you should do</h3>
        <p className="text-sm">{result.recommendation}</p>
      </section>

      <section>
        <h3 className="mb-2 font-semibold">Why this result</h3>
        <IndicatorList indicators={result.indicators} />
      </section>

      <AnalysisDetailsView result={result} />

      <section>
        <h3 className="mb-2 font-semibold">Threat-intelligence checks</h3>
        <ThreatIntelStatus threatIntel={result.threat_intel} />
      </section>

      <HistoryNotice result={result} />
      <ReportForm scanId={result.history?.scan_id} />

      <footer className="border-t border-slate-200 pt-3 text-xs text-slate-500 dark:border-slate-700 dark:text-slate-400">
        <p>{result.disclaimer}</p>
        <p className="mt-1">
          Request ID: <span className="font-mono">{result.request_id}</span>
          {result.engine_version ? ` · engine ${result.engine_version}` : ''}
        </p>
      </footer>
    </article>
  )
}
