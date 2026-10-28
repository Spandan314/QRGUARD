// Display helpers only. No security decisions are made in the app.
import type { Confidence, EvidenceSource, Severity } from '../types/api'

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

export const SOURCE_ORDER: EvidenceSource[] = ['threat_intelligence', 'message', 'link', 'qr', 'combination', 'ocr']

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

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

export function evidenceSource(indicator: { source?: EvidenceSource; module: string }): EvidenceSource {
  if (indicator.source) return indicator.source
  if (indicator.module === 'threat_intel') return 'threat_intelligence'
  if (indicator.module === 'message') return 'message'
  if (indicator.module === 'ocr') return 'ocr'
  return 'link'
}

/** "28 Oct 2026, 5:23 am" style: the month is spelled out, so day and month cannot be confused. */
export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}
