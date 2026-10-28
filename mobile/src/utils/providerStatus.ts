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
  timeout: 'Timed out – not checked',
  'rate limited': 'Rate limited – not checked',
  quota: 'Rate limited – not checked',
}

const ERROR_TEXT: Record<string, string> = {
  'auth key rejected': 'Key rejected – not checked',
  'auth key not received': 'Key missing – not checked',
}

export function providerState(p: ProviderResult): ProviderState {
  switch (p.status) {
    case 'listed':
      if (p.limited_coverage) return { outcome: 'flagged', label: 'Listed as malicious · demo list only' }
      return { outcome: 'flagged', label: p.detail ? `Listed as malicious (${p.detail})` : 'Listed as malicious' }
    case 'partial':
      return { outcome: 'flagged', label: p.detail ? `Flagged by some sources (${p.detail})` : 'Flagged by some sources' }
    case 'not_listed':
      return { outcome: 'checked', label: p.limited_coverage ? 'Not listed · demo list only' : 'Checked – not listed' }
    case 'unavailable':
      return { outcome: 'not_checked', label: UNAVAILABLE_TEXT[p.detail ?? ''] ?? 'Unavailable – not checked' }
    case 'error':
      return {
        outcome: 'not_checked',
        label: ERROR_TEXT[p.detail ?? ''] ?? (p.detail?.startsWith('auth') || p.detail?.startsWith('access') ? 'Key rejected – not checked' : 'Setup problem – not checked'),
      }
    case 'disabled':
      return { outcome: 'not_configured', label: 'Not configured' }
  }
}

/** One line on how many sources really answered, e.g. "2 of 5 sources checked this link …". */
export function providerSummary(block: ThreatIntelBlock): string {
  const states = block.providers.map(providerState)
  const count = (o: ProviderOutcome) => states.filter((s) => s.outcome === o).length
  const answered = count('checked') + count('flagged')
  const parts = [`${answered} of ${states.length} sources checked this link`]
  if (count('not_checked')) parts.push(`${count('not_checked')} could not`)
  if (count('not_configured')) parts.push(`${count('not_configured')} not configured`)
  const missing = count('not_checked') + count('not_configured')
  return parts.join(', ') + '.' + (missing ? ' A source that did not check this link says nothing about whether it is safe.' : '')
}
