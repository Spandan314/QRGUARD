import type { RiskLevel, VerdictLabel } from '../types/api'

export const colors = {
  brand: '#0f766e',
  brandDark: '#115e59',
  text: '#0f172a',
  muted: '#475569',
  border: '#cbd5e1',
  background: '#f1f5f9',
  card: '#ffffff',
  danger: '#b91c1c',
  utility: '#334155',
}

export const LEVEL_THEME: Record<RiskLevel, { icon: string; label: string; background: string; foreground: string; bar: string }> = {
  SAFE: { icon: '✅', label: 'SAFE', background: '#ecfdf5', foreground: '#064e3b', bar: '#059669' },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', background: '#fffbeb', foreground: '#78350f', bar: '#d97706' },
  MALICIOUS: { icon: '⛔', label: 'MALICIOUS', background: '#fef2f2', foreground: '#7f1d1d', bar: '#dc2626' },
}

type ThemeEntry = { icon: string; label: string; background: string; foreground: string; bar: string }

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_THEME: Record<VerdictLabel, ThemeEntry> = {
  SAFE: { icon: '✅', label: 'SAFE', background: '#ecfdf5', foreground: '#064e3b', bar: '#059669' },
  UNVERIFIED: { icon: '❔', label: 'NOT VERIFIED', background: '#f1f5f9', foreground: '#1e293b', bar: '#64748b' },
  SUSPICIOUS: LEVEL_THEME.SUSPICIOUS,
  MALICIOUS: LEVEL_THEME.MALICIOUS,
}

export const MIN_TOUCH = 48 // at least 44 pt touch targets (docs/architecture.md §3.3)
