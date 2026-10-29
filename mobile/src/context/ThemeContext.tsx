import AsyncStorage from '@react-native-async-storage/async-storage'
import { createContext, Fragment, useContext, useEffect, useState, type ReactNode } from 'react'
import { useColorScheme } from 'react-native'
import { applyTheme, type ThemeName } from '../constants/theme'

/** "system" follows the phone's light/dark setting. */
export type ThemeMode = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'qrguard.theme'
const MODES: ThemeMode[] = ['system', 'light', 'dark']

interface ThemeState {
  mode: ThemeMode
  theme: ThemeName
  setMode: (mode: ThemeMode) => void
}

const ThemeContext = createContext<ThemeState>({ mode: 'system', theme: 'dark', setMode: () => {} })

export function ThemeProvider({ children }: { children: ReactNode }) {
  const system = useColorScheme()
  const [mode, setModeState] = useState<ThemeMode>('system')

  useEffect(() => {
    AsyncStorage.getItem(STORAGE_KEY)
      .then((saved) => {
        if (saved && (MODES as string[]).includes(saved)) setModeState(saved as ThemeMode)
      })
      .catch(() => {})
  }, [])

  function setMode(next: ThemeMode) {
    setModeState(next)
    AsyncStorage.setItem(STORAGE_KEY, next).catch(() => {})
  }

  const theme: ThemeName = mode === 'system' ? (system === 'light' ? 'light' : 'dark') : mode
  // Colors are switched before the screens render; the key remounts them so every style is rebuilt.
  applyTheme(theme)
  return (
    <ThemeContext.Provider value={{ mode, theme, setMode }}>
      <Fragment key={theme}>{children}</Fragment>
    </ThemeContext.Provider>
  )
}

export function useTheme(): ThemeState {
  return useContext(ThemeContext)
}
