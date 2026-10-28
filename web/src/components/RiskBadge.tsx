import type { VerdictLabel } from '../types/api'
import { VERDICT_STYLE } from '../utils/format'
import { Icon } from './Icon'

/** Icon + word + colour, so the verdict never depends on colour alone. */
export function RiskBadge({ verdict, size = 'md' }: { verdict: VerdictLabel; size?: 'sm' | 'md' | 'lg' }) {
  const style = VERDICT_STYLE[verdict]
  const sizing = { sm: 'gap-1 px-1.5 py-0.5 text-[11px]', md: 'gap-1.5 px-2 py-1 text-xs', lg: 'gap-2 px-2.5 py-1 text-sm' }[size]
  const iconSize = { sm: 'h-3 w-3', md: 'h-3.5 w-3.5', lg: 'h-4 w-4' }[size]
  return (
    <span
      className={`inline-flex items-center rounded-md font-semibold tracking-wide ring-1 ring-inset ${style.classes} ${sizing}`}
      data-testid="risk-badge"
      data-icon={style.icon}
    >
      <Icon name={style.icon} className={iconSize} />
      {style.label}
    </span>
  )
}
