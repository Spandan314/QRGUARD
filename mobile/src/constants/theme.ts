import type { RiskLevel, VerdictLabel } from '../types/api'

// The website's "Airlock" dark palette (web/src/index.css), so the app and the site look alike.
export const colors = {
  brand: '#34e0b4', // accent: buttons, links, active tab
  brandDark: '#0a7a5e',
  onBrand: '#06231b', // text on an accent button
  text: '#e8eef3',
  muted: '#93a4b5',
  border: '#22303d',
  background: '#0a0f14',
  card: '#111922',
  card2: '#0e151c', // inputs and inset panels
  danger: '#ff6b5b',
  warn: '#ffb547',
  utility: '#93a4b5',
}

/**
 * The website's fonts: Inter for text, Space Grotesk for headings, JetBrains Mono for links and
 * codes. The expo-font plugin (app.config.ts) embeds them in the app as font families, so
 * `fontWeight` still picks the right weight. Where they are not embedded (Expo Go, tests), the
 * phone's system font is used.
 */
export const fonts = {
  sans: 'Inter',
  display: 'SpaceGrotesk',
  mono: 'JetBrainsMono',
}

export const LEVEL_THEME: Record<RiskLevel, { icon: string; label: string; background: string; foreground: string; bar: string }> = {
  SAFE: { icon: '✅', label: 'SAFE', background: '#0f2a24', foreground: '#34e0b4', bar: '#34e0b4' },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', background: '#2b2110', foreground: '#ffb547', bar: '#ffb547' },
  MALICIOUS: { icon: '⛔', label: 'MALICIOUS', background: '#2d1614', foreground: '#ff6b5b', bar: '#ff6b5b' },
}

type ThemeEntry = { icon: string; label: string; background: string; foreground: string; bar: string }

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_THEME: Record<VerdictLabel, ThemeEntry> = {
  SAFE: { icon: '✅', label: 'SAFE', background: '#0f2a24', foreground: '#34e0b4', bar: '#34e0b4' },
  UNVERIFIED: { icon: '❔', label: 'NOT VERIFIED', background: '#16202a', foreground: '#c3d0dc', bar: '#93a4b5' },
  SUSPICIOUS: LEVEL_THEME.SUSPICIOUS,
  MALICIOUS: LEVEL_THEME.MALICIOUS,
}

export const MIN_TOUCH = 48 // at least 44 pt touch targets (docs/architecture.md §3.3)
