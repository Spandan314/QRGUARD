// The inspection pass: a shareable ticket with the verdict. Built only from facts in the API
// response. It carries no verification QR and claims nothing it cannot back up; the shared text
// never contains a clickable copy of a checked link (hosts are "defanged": example[.]com).
import type { AnalysisResult, VerdictLabel } from '../types/api'
import { verdictOf } from './verdict'

export type Stamp = 'DENIED' | 'CAUTION' | 'CLEARED' | 'NOT VERIFIED'

/** NOT VERIFIED is never stamped CLEARED: missing evidence is not a clean bill. */
export const STAMP: Record<VerdictLabel, Stamp> = {
  MALICIOUS: 'DENIED',
  SUSPICIOUS: 'CAUTION',
  SAFE: 'CLEARED',
  UNVERIFIED: 'NOT VERIFIED',
}

export interface PassField {
  label: 'CLAIMS' | 'ACTUALLY' | 'FOUND' | 'CHECKED'
  value: string
}

export interface PassData {
  number: string
  title: string
  verdict: VerdictLabel
  stamp: Stamp
  fields: PassField[]
  advice: string
  /** Plain text for sharing (no clickable links). */
  shareText: string
}

/** "QG-" and the first eight letters/digits of the server's request ID. */
export function passNumber(requestId: string): string {
  const id = requestId.replace(/[^a-z0-9]/gi, '').slice(0, 8).toUpperCase()
  return `QG-${id || '00000000'}`
}

export const defang = (text: string) => text.replace(/\./g, '[.]')

const hostOf = (url: string) => {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
}

function subject(result: AnalysisResult): { title: string; isHost: boolean } {
  const a = result.analysis
  if (result.input_type === 'url') {
    const host = a.host_unicode ?? a.host ?? (a.normalized_url ? hostOf(a.normalized_url) : null)
    return host ? { title: host, isHost: true } : { title: 'A link', isHost: false }
  }
  if (result.input_type === 'qr' && a.qr) {
    const vpa = a.qr.parsed?.payee_vpa
    if (a.qr.content_type === 'upi' && typeof vpa === 'string' && vpa) return { title: `UPI QR · ${vpa}`, isHost: false }
    const host = a.qr.content_type === 'url' ? hostOf(a.qr.decoded_content) : null
    return host ? { title: host, isHost: true } : { title: 'A QR code', isHost: false }
  }
  return { title: result.input_type === 'screenshot' ? 'A screenshot' : 'A message', isHost: false }
}

const ADVICE: Record<VerdictLabel, string> = {
  MALICIOUS: 'Do not open it or pay it. Pass it on to family groups so nobody else falls for it.',
  SUSPICIOUS: 'Treat it with care. Check with the sender through a number or app you already trust.',
  SAFE: 'Recognised as genuine when it was checked. Still never share an OTP or PIN.',
  UNVERIFIED: 'Nothing bad was found, but QRGUARD could not confirm it is genuine.',
}

export function formatChecked(date: Date): string {
  const day = date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
  const time = date.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
  return `${day} · ${time}`
}

export function passData(result: AnalysisResult, checkedAt: Date): PassData {
  const verdict = verdictOf(result).label
  const a = result.analysis
  const { title, isHost } = subject(result)
  const fields: PassField[] = []

  const brand = a.brand
  const vpa = a.qr?.content_type === 'upi' ? a.qr.parsed?.payee_vpa : undefined
  const payee = a.qr?.content_type === 'upi' ? a.qr.parsed?.payee_name : undefined
  if (brand && a.domain) {
    fields.push({ label: 'CLAIMS', value: brand.brand })
    fields.push({ label: 'ACTUALLY', value: brand.match_type === 'official' ? `${brand.brand}'s own site` : `A site on ${a.domain}` })
  } else if (typeof payee === 'string' && payee && typeof vpa === 'string' && vpa) {
    fields.push({ label: 'CLAIMS', value: payee })
    fields.push({ label: 'ACTUALLY', value: `Pays UPI ID ${vpa}` })
  }

  const top = [...result.indicators].filter((i) => i.score_contribution > 0).sort((x, y) => y.score_contribution - x.score_contribution)[0]
  fields.push({ label: 'FOUND', value: top ? top.title : verdict === 'SAFE' ? 'No warning signs' : 'No warning signs, not confirmed' })
  fields.push({ label: 'CHECKED', value: formatChecked(checkedAt) })

  const number = passNumber(result.request_id)
  const stamp = STAMP[verdict]
  const shown = isHost ? defang(title) : title
  const found = fields.find((f) => f.label === 'FOUND')?.value ?? ''
  const shareText = `QRGUARD inspection pass ${number}: ${stamp}. ${shown}. Found: ${found}. ${ADVICE[verdict]}`
  return { number, title, verdict, stamp, fields, advice: ADVICE[verdict], shareText }
}
