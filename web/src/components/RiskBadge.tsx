import type { RiskLevel } from '../types/api'
import { LEVEL_STYLE } from '../utils/format'

/** Icon + word + colour, so the level never depends on colour alone. */
export function RiskBadge({ level, size = 'md' }: { level: RiskLevel; size?: 'sm' | 'md' | 'lg' }) {
  const style = LEVEL_STYLE[level]
  const sizing = { sm: 'px-2 py-0.5 text-xs', md: 'px-3 py-1 text-sm', lg: 'px-4 py-2 text-lg' }[size]
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-semibold ring-1 ring-inset ${style.classes} ${sizing}`}
      data-testid="risk-badge"
    >
      <span aria-hidden="true">{style.icon}</span>
      {level}
    </span>
  )
}
