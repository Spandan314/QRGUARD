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

// Accent, warn and danger are reserved for verdicts and warnings; everything else is neutral.
export const LEVEL_STYLE: Record<RiskLevel, StateStyle> = {
  SAFE: {
    icon: 'shield-check',
    label: 'Safe',
    classes: 'bg-accent/10 text-accent ring-accent/40',
    bar: 'bg-accent',
    accent: 'border-accent text-accent',
  },
  SUSPICIOUS: {
    icon: 'alert-triangle',
    label: 'Suspicious',
    classes: 'bg-warn/10 text-warn ring-warn/40',
    bar: 'bg-warn',
    accent: 'border-warn text-warn',
  },
  MALICIOUS: {
    icon: 'x-octagon',
    label: 'Malicious',
    classes: 'bg-danger/10 text-danger ring-danger/40',
    bar: 'bg-danger',
    accent: 'border-danger text-danger',
  },
}

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_STYLE: Record<VerdictLabel, StateStyle> = {
  SAFE: { ...LEVEL_STYLE.SAFE, label: 'SAFE' },
  UNVERIFIED: {
    icon: 'help',
    label: 'NOT VERIFIED',
    classes: 'bg-panel-2 text-muted ring-line',
    bar: 'bg-muted',
    accent: 'border-line text-muted',
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
  critical: 'bg-danger/10 text-danger ring-1 ring-inset ring-danger/40',
  high: 'bg-danger/10 text-danger ring-1 ring-inset ring-danger/25',
  medium: 'bg-warn/10 text-warn ring-1 ring-inset ring-warn/40',
  low: 'bg-panel-2 text-muted ring-1 ring-inset ring-line',
  info: 'bg-panel-2 text-muted ring-1 ring-inset ring-line',
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
