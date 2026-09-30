// Policy for opening links from results (docs/architecture.md §3.3). Used by OpenLinkGuard, the
// only code path that opens external URLs. The app never opens a link on its own.
import type { RiskLevel } from '../types/api'

export type LinkAction = 'confirm' | 'warn' | 'copy-only' | 'never'

/** Only plain web links can ever be opened; intent:, javascript:, data:, file: etc. never. */
export function isOpenableUrl(url: string): boolean {
  return /^https?:\/\/[^\s/?#]+/i.test(url.trim()) && !/[\s<>"]/.test(url.trim())
}

export function linkAction(url: string, level: RiskLevel): LinkAction {
  if (!isOpenableUrl(url)) return 'never'
  if (level === 'MALICIOUS') return 'copy-only'
  if (level === 'SUSPICIOUS') return 'warn'
  return 'confirm'
}
