import type { RiskLevel, VerdictLabel } from '../types/api'

export type ThemeName = 'dark' | 'light'

// The website's "Airlock" palettes (web/src/index.css), so the app and the site look alike.
const PALETTES = {
  dark: {
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
    dangerBackground: '#2d1614',
    dangerBorder: '#7a2e27',
    warn: '#ffb547',
    utility: '#93a4b5',
  },
  light: {
    brand: '#0a7a5e',
    brandDark: '#075c47',
    onBrand: '#ffffff',
    text: '#0b1219',
    muted: '#51606f',
    border: '#d7dee5',
    background: '#f4f6f8',
    card: '#ffffff',
    card2: '#f7f9fa',
    danger: '#b42318',
    dangerBackground: '#fdeceb',
    dangerBorder: '#f3b4ad',
    warn: '#8a4b00',
    utility: '#51606f',
  },
}

type Palette = (typeof PALETTES)['dark']

/** The active palette. Its values change in place when the theme changes (see applyTheme). */
export const colors: Palette = { ...PALETTES.dark }

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

type ThemeEntry = { icon: string; label: string; background: string; foreground: string; bar: string }
type LevelColors = Pick<ThemeEntry, 'background' | 'foreground' | 'bar'>

const LEVEL_COLORS: Record<ThemeName, Record<RiskLevel | 'UNVERIFIED', LevelColors>> = {
  dark: {
    SAFE: { background: '#0f2a24', foreground: '#34e0b4', bar: '#34e0b4' },
    SUSPICIOUS: { background: '#2b2110', foreground: '#ffb547', bar: '#ffb547' },
    MALICIOUS: { background: '#2d1614', foreground: '#ff6b5b', bar: '#ff6b5b' },
    UNVERIFIED: { background: '#16202a', foreground: '#c3d0dc', bar: '#93a4b5' },
  },
  light: {
    SAFE: { background: '#e6f4ef', foreground: '#0a7a5e', bar: '#0a7a5e' },
    SUSPICIOUS: { background: '#fdf3e3', foreground: '#8a4b00', bar: '#b86e00' },
    MALICIOUS: { background: '#fdeceb', foreground: '#b42318', bar: '#b42318' },
    UNVERIFIED: { background: '#eef1f4', foreground: '#3a4856', bar: '#51606f' },
  },
}

export const LEVEL_THEME: Record<RiskLevel, ThemeEntry> = {
  SAFE: { icon: '✅', label: 'SAFE', ...LEVEL_COLORS.dark.SAFE },
  SUSPICIOUS: { icon: '⚠️', label: 'SUSPICIOUS', ...LEVEL_COLORS.dark.SUSPICIOUS },
  MALICIOUS: { icon: '⛔', label: 'MALICIOUS', ...LEVEL_COLORS.dark.MALICIOUS },
}

/** The headline verdict. UNVERIFIED is neutral: neither a warning nor a promise of safety. */
export const VERDICT_THEME: Record<VerdictLabel, ThemeEntry> = {
  SAFE: { icon: '✅', label: 'SAFE', ...LEVEL_COLORS.dark.SAFE },
  UNVERIFIED: { icon: '❔', label: 'NOT VERIFIED', ...LEVEL_COLORS.dark.UNVERIFIED },
  SUSPICIOUS: LEVEL_THEME.SUSPICIOUS,
  MALICIOUS: LEVEL_THEME.MALICIOUS,
}

let currentTheme: ThemeName = 'dark'
let themeVersion = 0

export function activeTheme(): ThemeName {
  return currentTheme
}

/** Switches every color in place. Screens must re-render afterwards (ThemeProvider remounts them). */
export function applyTheme(name: ThemeName): void {
  if (name === currentTheme) return
  currentTheme = name
  themeVersion += 1
  Object.assign(colors, PALETTES[name])
  const levels = LEVEL_COLORS[name]
  for (const level of ['SAFE', 'SUSPICIOUS', 'MALICIOUS'] as const) Object.assign(LEVEL_THEME[level], levels[level])
  Object.assign(VERDICT_THEME.SAFE, levels.SAFE)
  Object.assign(VERDICT_THEME.UNVERIFIED, levels.UNVERIFIED)
}

/**
 * Styles that use theme colors. `StyleSheet.create` runs once, so its colors would stay those of the
 * theme at start-up; this rebuilds the styles the first time they are read after a theme change.
 */
export function themedStyles<T extends object>(build: () => T): T {
  let built = build()
  let version = themeVersion
  return new Proxy({} as T, {
    get(_target, key) {
      if (version !== themeVersion) {
        built = build()
        version = themeVersion
      }
      return built[key as keyof T]
    },
  })
}

export const MIN_TOUCH = 48 // at least 44 pt touch targets (docs/architecture.md §3.3)
