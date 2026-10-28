import type { ThreatIntelBlock } from '../types/api'
import { PROVIDER_NAME } from '../utils/format'
import { providerState, providerSummary, type ProviderOutcome } from '../utils/providerStatus'

const OUTCOME_STYLE: Record<ProviderOutcome, { icon: string; classes: string }> = {
  flagged: { icon: '⛔', classes: 'font-semibold text-red-700 dark:text-red-300' },
  checked: { icon: '✓', classes: 'text-slate-700 dark:text-slate-200' },
  not_checked: { icon: '⚠', classes: 'font-medium text-amber-800 dark:text-amber-300' },
  not_configured: { icon: '–', classes: 'text-slate-500 dark:text-slate-400' },
}

export function ThreatIntelStatus({ threatIntel }: { threatIntel: ThreatIntelBlock }) {
  return (
    <div className="text-sm">
      {threatIntel.providers.length > 0 ? (
        <>
          <p className="mb-2 font-medium" data-testid="ti-summary">
            {providerSummary(threatIntel)}
          </p>
          <ul className="grid gap-1 sm:grid-cols-2">
            {threatIntel.providers.map((provider) => {
              const state = providerState(provider)
              const style = OUTCOME_STYLE[state.outcome]
              return (
                <li
                  key={provider.provider}
                  className="flex flex-wrap justify-between gap-2 rounded bg-slate-50 px-2 py-1 dark:bg-slate-800"
                  data-testid="ti-provider"
                  data-outcome={state.outcome}
                >
                  <span>{PROVIDER_NAME[provider.provider] ?? provider.provider}</span>
                  <span className={style.classes}>
                    <span aria-hidden="true">{style.icon} </span>
                    {state.label}
                  </span>
                </li>
              )
            })}
          </ul>
        </>
      ) : null}
      <p className="mt-2 text-slate-600 dark:text-slate-300">{threatIntel.note}</p>
    </div>
  )
}
