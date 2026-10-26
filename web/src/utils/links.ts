// Policy for opening links from results (same rules as mobile/src/utils/links.ts). Used by OpenCheckedLink, the
// only code path that opens external URLs. The app never opens a link on its own, never changes
// it, and only ever opens the exact URL that was checked.
import type { VerdictLabel } from '../types/api'

export type LinkAction = 'confirm' | 'caution' | 'warn' | 'copy-only' | 'never'

const AUTHORITY = /^https?:\/\/([^/?#]*)/i
const HOST = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i
const IPV6 = /^\[[0-9a-f:.]+\]$/i

function hasControlCharacter(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return true
  }
  return false
}

/** The host[:port] part of an http(s) link, or null. */
function authorityOf(url: string): string | null {
  return AUTHORITY.exec(url)?.[1] ?? null
}

/** Only plain http(s) web links with a valid host; intent:, javascript:, data:, file: etc. never. */
export function isOpenableUrl(url: string): boolean {
  const text = url.trim()
  if (text !== url || /[\s<>"'`\\]/.test(text) || hasControlCharacter(text)) return false
  const authority = authorityOf(text)
  if (!authority || authority.includes('@')) return false
  const host = authority.replace(/:\d{1,5}$/, '')
  return HOST.test(host) || IPV6.test(host)
}

/** The domain shown in confirmations, so the user sees exactly where they would go. */
export function hostOf(url: string): string | null {
  const authority = authorityOf(url)
  if (!authority) return null
  return authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d{1,5}$/, '').toLowerCase()
}

/** Links with "user@" before the host are a known disguise; they are never opened. */
export function hasUserInfo(url: string): boolean {
  return (authorityOf(url) ?? '').includes('@')
}

export function linkAction(url: string, verdict: VerdictLabel): LinkAction {
  if (!isOpenableUrl(url)) return 'never'
  if (verdict === 'MALICIOUS') return 'copy-only'
  if (verdict === 'SUSPICIOUS') return 'warn'
  if (verdict === 'UNVERIFIED') return 'caution'
  return 'confirm'
}
