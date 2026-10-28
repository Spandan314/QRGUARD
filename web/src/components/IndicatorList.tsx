import type { EvidenceSource, Indicator } from '../types/api'
import { SEVERITY_ORDER, SEVERITY_STYLE, SOURCE_LABEL, SOURCE_ORDER, formatPoints } from '../utils/format'

function sourceOf(indicator: Indicator): EvidenceSource {
  if (indicator.source) return indicator.source
  if (indicator.module === 'threat_intel') return 'threat_intelligence'
  if (indicator.module === 'message') return 'message'
  if (indicator.module === 'ocr') return 'ocr'
  return 'link'
}

/** Why the score is what it is: indicators grouped by where the evidence came from. */
export function IndicatorList({ indicators }: { indicators: Indicator[] }) {
  if (indicators.length === 0) {
    return <p className="text-sm text-slate-600 dark:text-slate-300">No warning signs were found.</p>
  }
  const groups = new Map<EvidenceSource, Indicator[]>()
  for (const indicator of indicators) {
    const key = sourceOf(indicator)
    groups.set(key, [...(groups.get(key) ?? []), indicator])
  }
  return (
    <div className="space-y-4">
      {SOURCE_ORDER.filter((source) => groups.has(source)).map((source) => (
        <section key={source} aria-label={SOURCE_LABEL[source]}>
          <h4 className="mb-1.5 text-sm font-medium text-slate-700 dark:text-slate-200">
            {SOURCE_LABEL[source]}
          </h4>
          <ul className="divide-y divide-slate-100 rounded-md border border-slate-200 dark:divide-slate-800 dark:border-slate-700">
            {[...(groups.get(source) ?? [])]
              .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity])
              .map((indicator, index) => (
                <li
                  key={`${indicator.id}-${index}`}
                  className="px-3 py-2.5"
                  data-testid="indicator"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-sm font-medium">{indicator.title}</span>
                    <span className="flex items-center gap-2 text-xs">
                      <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${SEVERITY_STYLE[indicator.severity]}`}>
                        {indicator.severity}
                      </span>
                      <span
                        className="w-14 text-right font-mono tabular-nums text-slate-600 dark:text-slate-300"
                        title="Points this sign added to the final score"
                      >
                        {formatPoints(indicator.score_contribution)} pts
                      </span>
                    </span>
                  </div>
                  <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-300">{indicator.message}</p>
                  {indicator.evidence ? (
                    <p className="mt-1 break-all text-xs text-slate-500 dark:text-slate-400">
                      Evidence: <span className="font-mono">{indicator.evidence}</span>
                    </p>
                  ) : null}
                </li>
              ))}
          </ul>
        </section>
      ))}
    </div>
  )
}
