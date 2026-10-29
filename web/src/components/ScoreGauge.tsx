import type { RiskLevel } from '../types/api'
import { LEVEL_STYLE } from '../utils/format'

/** Compact 0–100 risk meter with the two band boundaries marked (the number is shown beside it). */
export function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const clamped = Math.max(0, Math.min(100, score))
  return (
    <div className="w-full">
      <div
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        aria-valuetext={`${clamped} out of 100, ${level}`}
        className="relative h-1.5 w-full overflow-hidden rounded-full bg-line"
      >
        <div className={`h-full ${LEVEL_STYLE[level].bar}`} style={{ width: `${clamped}%` }} />
        {/* band boundaries at 30 and 60 */}
        <div className="absolute inset-y-0 left-[30%] w-0.5 bg-panel-2" aria-hidden="true" />
        <div className="absolute inset-y-0 left-[60%] w-0.5 bg-panel-2" aria-hidden="true" />
      </div>
      <div className="relative mt-1 h-4 text-[11px] text-muted" aria-hidden="true">
        <span className="absolute left-0">0</span>
        <span className="absolute left-[30%] -translate-x-1/2" title="Suspicious from 30">30</span>
        <span className="absolute left-[60%] -translate-x-1/2" title="Malicious from 60">60</span>
        <span className="absolute right-0">100</span>
      </div>
    </div>
  )
}
