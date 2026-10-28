// Display helpers only. No security decisions are made in the web app.
import type { IconName } from '../components/Icon'
import type { Confidence, EvidenceSource, RiskLevel, Severity, VerdictLabel } from '../types/api'

type StateStyle = {
  icon: IconName
  label: string
  /** Badge colours. */
  classes: string
  /** Score bar fill. */
  bar: string
  /** Left accent and icon colour of the verdict panel. */
  accent: string
}

// Red, amber and green are reserved for security states; everything else is neutral.
export const LEVEL_STYLE: Record<RiskLevel, StateStyle> = {
  SAFE: {
    icon: 'shield-check',
    label: 'Safe',
    classes: 'bg-emerald-50 text-emerald-800 ring-emerald-600/25 dark:bg-emerald-950 dark:text-emerald-200',
    bar: 'bg-emerald-600',
    accent: 'border-emerald-600 text-emerald-700 dark:text-emerald-400',
  },
  SUSPICIOUS: {
    icon: 'alert-triangle',
    label: 'Suspicious',
    classes: 'bg-amber-50 text-amber-800 ring-amber-600/25 dark:bg-amber-950 dark:text-amber-200',
    bar: 'bg-amber-500',
    accent: 'border-amber-500 text-amber-700 dark:text-amber-400',
  },
  MALICIOUS: {
    icon: 'x-octagon',
    label: 'Malicious',
    classes: 'bg-red-50 text-red-800 ring-red-600/25 dark:bg-red-950 dark:text-red-200',
    bar: 'bg-red-600',
    accent: 'border-red-600 text-red-700 dark:text-red-400',
  },
}

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_STYLE: Record<VerdictLabel, StateStyle> = {
  SAFE: { ...LEVEL_STYLE.SAFE, label: 'SAFE' },
  UNVERIFIED: {
    icon: 'help',
    label: 'NOT VERIFIED',
    classes: 'bg-slate-100 text-slate-700 ring-slate-500/25 dark:bg-slate-800 dark:text-slate-200',
    bar: 'bg-slate-500',
    accent: 'border-slate-400 text-slate-600 dark:text-slate-300',
  },
  SUSPICIOUS: { ...LEVEL_STYLE.SUSPICIOUS, label: 'SUSPICIOUS' },
  MALICIOUS: { ...LEVEL_STYLE.MALICIOUS, label: 'MALICIOUS' },
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
  critical: 'bg-red-50 text-red-800 ring-1 ring-inset ring-red-600/30 dark:bg-red-950 dark:text-red-200',
  high: 'bg-red-50 text-red-700 ring-1 ring-inset ring-red-600/15 dark:bg-red-950 dark:text-red-300',
  medium: 'bg-amber-50 text-amber-800 ring-1 ring-inset ring-amber-600/25 dark:bg-amber-950 dark:text-amber-200',
  low: 'bg-slate-100 text-slate-700 ring-1 ring-inset ring-slate-500/20 dark:bg-slate-800 dark:text-slate-200',
  info: 'bg-slate-50 text-slate-600 ring-1 ring-inset ring-slate-400/20 dark:bg-slate-800 dark:text-slate-300',
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
