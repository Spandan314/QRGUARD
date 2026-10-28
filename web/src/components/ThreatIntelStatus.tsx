import type { ThreatIntelBlock } from '../types/api'
import { PROVIDER_NAME } from '../utils/format'
import { providerState, providerSummary, type ProviderOutcome } from '../utils/providerStatus'
import { Icon, type IconName } from './Icon'

const OUTCOME_STYLE: Record<ProviderOutcome, { icon: IconName; classes: string; iconClasses: string }> = {
  flagged: { icon: 'x-octagon', classes: 'font-semibold text-red-700 dark:text-red-300', iconClasses: 'text-red-600' },
  checked: { icon: 'check', classes: 'text-slate-700 dark:text-slate-200', iconClasses: 'text-teal-700 dark:text-teal-400' },
  not_checked: { icon: 'alert-triangle', classes: 'font-medium text-amber-800 dark:text-amber-300', iconClasses: 'text-amber-600' },
  not_configured: { icon: 'minus', classes: 'text-slate-500 dark:text-slate-400', iconClasses: 'text-slate-400' },
}

export function ThreatIntelStatus({ threatIntel }: { threatIntel: ThreatIntelBlock }) {
  return (
    <div className="text-sm">
      {threatIntel.providers.length > 0 ? (
        <>
          <p className="mb-2 text-slate-700 dark:text-slate-200" data-testid="ti-summary">
            {providerSummary(threatIntel)}
          </p>
          <div className="overflow-x-auto rounded-md border border-slate-200 dark:border-slate-700">
            <table className="w-full text-left">
              <thead className="bg-slate-50 text-xs uppercase tracking-wider text-slate-500 dark:bg-slate-950 dark:text-slate-400">
                <tr>
                  <th scope="col" className="px-3 py-2 font-semibold">
                    Source
                  </th>
                  <th scope="col" className="px-3 py-2 font-semibold">
                    Result
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                {threatIntel.providers.map((provider) => {
                  const state = providerState(provider)
                  const style = OUTCOME_STYLE[state.outcome]
                  return (
                    <tr key={provider.provider} data-testid="ti-provider" data-outcome={state.outcome}>
                      <td className="whitespace-nowrap px-3 py-2">{PROVIDER_NAME[provider.provider] ?? provider.provider}</td>
                      <td className={`px-3 py-2 ${style.classes}`}>
                        <span className="inline-flex items-center gap-1.5">
                          <Icon name={style.icon} className={`h-4 w-4 ${style.iconClasses}`} />
                          {state.label}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{threatIntel.note}</p>
    </div>
  )
}
