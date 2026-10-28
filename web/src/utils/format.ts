// Display helpers only. No security decisions are made in the web app.
import type { Confidence, EvidenceSource, RiskLevel, Severity, VerdictLabel } from '../types/api'

export const LEVEL_STYLE: Record<RiskLevel, { icon: string; label: string; classes: string; bar: string }> = {
  SAFE: {
    icon: '✅',
    label: 'Safe',
    classes: 'bg-emerald-50 text-emerald-900 ring-emerald-600/30 dark:bg-emerald-950 dark:text-emerald-100',
    bar: 'bg-emerald-600',
  },
  SUSPICIOUS: {
    icon: '⚠️',
    label: 'Suspicious',
    classes: 'bg-amber-50 text-amber-900 ring-amber-600/30 dark:bg-amber-950 dark:text-amber-100',
    bar: 'bg-amber-500',
  },
  MALICIOUS: {
    icon: '⛔',
    label: 'Malicious',
    classes: 'bg-red-50 text-red-900 ring-red-600/30 dark:bg-red-950 dark:text-red-100',
    bar: 'bg-red-600',
  },
}

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_STYLE: Record<VerdictLabel, { icon: string; label: string; classes: string }> = {
  SAFE: { icon: '✅', label: 'SAFE', classes: LEVEL_STYLE.SAFE.classes },
  UNVERIFIED: {
    icon: '❔',
    label: 'NOT VERIFIED',
    classes: 'bg-slate-100 text-slate-900 ring-slate-500/30 dark:bg-slate-800 dark:text-slate-100',
  },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', classes: LEVEL_STYLE.SUSPICIOUS.classes },
  MALICIOUS: { icon: '⛔', label: 'MALICIOUS', classes: LEVEL_STYLE.MALICIOUS.classes },
}

export const CONFIDENCE_TEXT: Record<Confidence, string> = {
  HIGH: 'High confidence',
  MEDIUM: 'Medium confidence',
  LOW: 'Low confidence – some checks could not be completed or there is little evidence',
}

export const SOURCE_LABEL: Record<EvidenceSource, string> = {
  message: 'Message text',
  link: 'Link',
  qr: 'QR code content',
  threat_intelligence: 'Threat intelligence',
  combination: 'Combination of signs',
  ocr: 'Text recognition (OCR)',
}

export const SOURCE_ORDER: EvidenceSource[] = [
  'threat_intelligence',
  'message',
  'link',
  'qr',
  'combination',
  'ocr',
]

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

export const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-red-700 text-white',
  high: 'bg-red-100 text-red-900 dark:bg-red-900 dark:text-red-100',
  medium: 'bg-amber-100 text-amber-900 dark:bg-amber-900 dark:text-amber-100',
  low: 'bg-slate-200 text-slate-800 dark:bg-slate-700 dark:text-slate-100',
  info: 'bg-sky-100 text-sky-900 dark:bg-sky-900 dark:text-sky-100',
}

export const PROVIDER_NAME: Record<string, string> = {
  local_feed: 'Local blocklist',
  urlhaus: 'URLhaus',
  google_safe_browsing: 'Google Safe Browsing',
  virustotal: 'VirusTotal',
  phishtank: 'PhishTank',
}


export function formatPoints(points: number): string {
  const rounded = Math.round(points * 10) / 10
  if (rounded === 0) return '0'
  return rounded > 0 ? `+${rounded}` : `${rounded}`
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** "28 Oct 2026, 5:23 am" style: the month is spelled out, so day and month cannot be confused. */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
