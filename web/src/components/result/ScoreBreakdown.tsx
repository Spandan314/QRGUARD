import { formatPoints } from '../../utils/format'
import type { BreakdownRow } from '../../utils/result'

/** "Why <score>": each sign's points, a floor if one applied, and the final score. */
export function ScoreBreakdown({ rows, total, tone }: { rows: BreakdownRow[]; total: number; tone: string }) {
  return (
    <section aria-labelledby="why-title" className="rounded-panel border border-line bg-panel p-5" data-testid="score-breakdown">
      <h3 id="why-title" className="font-display text-lg font-semibold">
        Why {total}
      </h3>
      {rows.length ? (
        <ul className="mt-3 divide-y divide-line text-sm">
          {rows.map((row, i) => (
            <li key={i} className="flex items-start justify-between gap-4 py-2.5">
              <span className="min-w-0 break-words">{row.label}</span>
              <span className={`shrink-0 font-mono font-semibold tabular-nums ${row.points > 0 ? tone : 'text-accent'}`}>{formatPoints(row.points)}</span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-3 text-sm text-muted">No sign added points. A low score is not proof of safety.</p>
      )}
      <p className="mt-2 flex justify-between border-t-2 border-ink pt-2.5 text-sm font-semibold">
        <span>Risk score</span>
        <span className="font-mono tabular-nums">{total}</span>
      </p>
    </section>
  )
}
