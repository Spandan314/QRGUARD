// What each threat-intelligence source did for this check, in words a user can act on (the same
// helper exists in web/ and mobile/). A source that could not answer is NEVER shown as a clean
// result: "not checked" is not evidence that a link is safe.
import type { ProviderResult, ThreatIntelBlock } from '../types/api'

export type ProviderOutcome = 'flagged' | 'checked' | 'not_checked' | 'not_configured'

export interface ProviderState {
  outcome: ProviderOutcome
  /** Short status, e.g. "Rate limited – not checked". */
  label: string
}

const UNAVAILABLE_TEXT: Record<string, string> = {
  timeout: 'Too slow to answer – not checked',
  'rate limited': 'Busy, try later – not checked',
  quota: 'Busy, try later – not checked',
}

const ERROR_TEXT: Record<string, string> = {
  'auth key rejected': 'Key rejected – not checked',
  'auth key not received': 'Key missing – not checked',
}

export function providerState(p: ProviderResult): ProviderState {
  switch (p.status) {
    case 'listed':
      if (p.limited_coverage) return { outcome: 'flagged', label: 'On our test list only (demo data)' }
      return { outcome: 'flagged', label: p.detail ? `Listed as dangerous (${p.detail})` : 'Listed as dangerous' }
    case 'partial':
      return { outcome: 'flagged', label: p.detail ? `Flagged by some sources (${p.detail})` : 'Flagged by some sources' }
    case 'not_listed':
      return { outcome: 'checked', label: p.limited_coverage ? 'Not on our test list (demo data)' : 'Checked – not on the list' }
    case 'unavailable':
      return { outcome: 'not_checked', label: UNAVAILABLE_TEXT[p.detail ?? ''] ?? 'Did not answer – not checked' }
    case 'error':
      return {
        outcome: 'not_checked',
        label: ERROR_TEXT[p.detail ?? ''] ?? (p.detail?.startsWith('auth') || p.detail?.startsWith('access') ? 'Key rejected – not checked' : 'Setup problem – not checked'),
      }
    case 'disabled':
      return { outcome: 'not_configured', label: 'Not set up' }
  }
}

/** One line on how many sources really answered, e.g. "2 of 5 sources checked this link …". */
export function providerSummary(block: ThreatIntelBlock): string {
  const states = uniqueProviders(block.providers).map(providerState)
  const count = (o: ProviderOutcome) => states.filter((s) => s.outcome === o).length
  const answered = count('checked') + count('flagged')
  const parts = [`${answered} of ${states.length} scam databases checked this`]
  if (count('not_checked')) parts.push(`${count('not_checked')} did not answer`)
  if (count('not_configured')) parts.push(`${count('not_configured')} not set up`)
  const missing = count('not_checked') + count('not_configured')
  return parts.join(', ') + '.' + (missing ? ' A database that did not check it tells us nothing either way.' : '')
}

const OUTCOME_RANK: Record<ProviderOutcome, number> = { flagged: 3, not_checked: 2, checked: 1, not_configured: 0 }

/**
 * One row per provider. A shortened link is looked up twice (the short address and where it
 * leads), so each provider can answer twice: keep its most serious answer, never the cleaner one.
 */
export function uniqueProviders(providers: ProviderResult[]): ProviderResult[] {
  const best = new Map<string, ProviderResult>()
  for (const p of providers) {
    const current = best.get(p.provider)
    if (!current || OUTCOME_RANK[providerState(p).outcome] > OUTCOME_RANK[providerState(current).outcome]) best.set(p.provider, p)
  }
  return [...best.values()]
}
