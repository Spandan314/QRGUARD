import type { ThreatIntelBlock } from '../types/api'
import { PROVIDER_NAME } from '../utils/format'
import { providerState, providerSummary, uniqueProviders, type ProviderOutcome } from '../utils/providerStatus'
import { Icon, type IconName } from './Icon'

const OUTCOME_STYLE: Record<ProviderOutcome, { icon: IconName; classes: string; iconClasses: string }> = {
  flagged: { icon: 'x-octagon', classes: 'font-semibold text-danger', iconClasses: 'text-danger' },
  checked: { icon: 'check', classes: 'text-ink', iconClasses: 'text-accent' },
  not_checked: { icon: 'alert-triangle', classes: 'font-medium text-warn', iconClasses: 'text-warn' },
  not_configured: { icon: 'minus', classes: 'text-muted', iconClasses: 'text-muted' },
}

export function ThreatIntelStatus({ threatIntel }: { threatIntel: ThreatIntelBlock }) {
  return (
    <div className="text-sm">
      {threatIntel.providers.length > 0 ? (
        <>
          <p className="mb-2 text-ink" data-testid="ti-summary">
            {providerSummary(threatIntel)}
          </p>
          <div className="overflow-x-auto rounded-btn border border-line">
            <table className="w-full text-left">
              <thead className="bg-panel-2 text-xs uppercase tracking-wider text-muted">
                <tr>
                  <th scope="col" className="px-3 py-2 font-semibold">
                    Source
                  </th>
                  <th scope="col" className="px-3 py-2 font-semibold">
                    Result
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {uniqueProviders(threatIntel.providers).map((provider) => {
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
      <p className="mt-2 text-xs text-muted">{threatIntel.note}</p>
    </div>
  )
}
