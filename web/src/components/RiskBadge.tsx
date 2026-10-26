import type { VerdictLabel } from '../types/api'
import { VERDICT_STYLE } from '../utils/format'

/** Icon + word + colour, so the verdict never depends on colour alone. */
export function RiskBadge({ verdict, size = 'md' }: { verdict: VerdictLabel; size?: 'sm' | 'md' | 'lg' }) {
  const style = VERDICT_STYLE[verdict]
  const sizing = { sm: 'px-2 py-0.5 text-xs', md: 'px-3 py-1 text-sm', lg: 'px-4 py-2 text-lg' }[size]
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-semibold ring-1 ring-inset ${style.classes} ${sizing}`}
      data-testid="risk-badge"
    >
      <span aria-hidden="true">{style.icon}</span>
      {style.label}
    </span>
  )
}
