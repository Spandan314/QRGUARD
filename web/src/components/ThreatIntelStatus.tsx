import type { ThreatIntelBlock } from '../types/api'
import { PROVIDER_NAME, TI_STATUS_TEXT } from '../utils/format'

export function ThreatIntelStatus({ threatIntel }: { threatIntel: ThreatIntelBlock }) {
  return (
    <div className="text-sm">
      {threatIntel.providers.length > 0 ? (
        <ul className="grid gap-1 sm:grid-cols-2">
          {threatIntel.providers.map((provider) => (
            <li key={provider.provider} className="flex flex-wrap justify-between gap-2 rounded bg-slate-50 px-2 py-1 dark:bg-slate-800">
              <span>{PROVIDER_NAME[provider.provider] ?? provider.provider}</span>
              <span
                className={
                  provider.status === 'listed' || provider.status === 'partial'
                    ? 'font-semibold text-red-700 dark:text-red-300'
                    : 'text-slate-600 dark:text-slate-300'
                }
              >
                {TI_STATUS_TEXT[provider.status]}
                {provider.detail ? ` (${provider.detail})` : ''}
                {provider.limited_coverage ? ' · demo list only' : ''}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-2 text-slate-600 dark:text-slate-300">{threatIntel.note}</p>
    </div>
  )
}
