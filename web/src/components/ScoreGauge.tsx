import type { RiskLevel } from '../types/api'
import { LEVEL_STYLE } from '../utils/format'

export function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const clamped = Math.max(0, Math.min(100, score))
  return (
    <div className="w-full">
      <div className="flex items-baseline justify-between text-sm">
        <span className="font-medium">Risk score</span>
        <span>
          <span className="text-2xl font-bold">{clamped}</span>
          <span className="text-slate-500 dark:text-slate-400"> / 100</span>
        </span>
      </div>
      <div
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={clamped}
        aria-valuetext={`${clamped} out of 100, ${level}`}
        className="relative mt-2 h-3 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700"
      >
        <div className={`h-full ${LEVEL_STYLE[level].bar}`} style={{ width: `${clamped}%` }} />
        {/* level boundaries at 30 and 60 */}
        <div className="absolute inset-y-0 left-[30%] w-px bg-white/80" aria-hidden="true" />
        <div className="absolute inset-y-0 left-[60%] w-px bg-white/80" aria-hidden="true" />
      </div>
      <div className="mt-1 flex justify-between text-xs text-slate-500 dark:text-slate-400" aria-hidden="true">
        <span>0 Safe</span>
        <span>30 Suspicious</span>
        <span>60 Malicious</span>
        <span>100</span>
      </div>
    </div>
  )
}
