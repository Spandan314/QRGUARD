import AsyncStorage from '@react-native-async-storage/async-storage'
import { fireEvent, render, screen } from '@testing-library/react-native'
import { StyleSheet, Text } from 'react-native'
import { applyTheme, colors, LEVEL_THEME, themedStyles, VERDICT_THEME } from '../constants/theme'
import { ThemeProvider, useTheme } from '../context/ThemeContext'

afterEach(() => applyTheme('dark'))

describe('theme', () => {
  it('switches every palette color and the verdict colors in place', () => {
    applyTheme('light')
    expect(colors.background).toBe('#f4f6f8')
    expect(colors.text).toBe('#0b1219')
    expect(LEVEL_THEME.MALICIOUS.foreground).toBe('#b42318')
    expect(VERDICT_THEME.MALICIOUS.foreground).toBe('#b42318')
    expect(VERDICT_THEME.UNVERIFIED.label).toBe('NOT VERIFIED')
    applyTheme('dark')
    expect(colors.background).toBe('#0a0f14')
    expect(LEVEL_THEME.SAFE.bar).toBe('#34e0b4')
  })

  it('rebuilds themed styles after a theme change', () => {
    const styles = themedStyles(() => StyleSheet.create({ box: { backgroundColor: colors.card } }))
    expect(styles.box.backgroundColor).toBe('#111922')
    applyTheme('light')
    expect(styles.box.backgroundColor).toBe('#ffffff')
  })

  it('remembers the chosen appearance', async () => {
    function Probe() {
      const { theme, setMode } = useTheme()
      return (
        <Text onPress={() => setMode('light')} testID="probe">
          {theme}
        </Text>
      )
    }
    await render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    await fireEvent.press(screen.getByTestId('probe'))
    expect(await screen.findByText('light')).toBeOnTheScreen()
    expect(colors.background).toBe('#f4f6f8')
    expect(await AsyncStorage.getItem('qrguard.theme')).toBe('light')
  })

  it('starts with a saved choice', async () => {
    await AsyncStorage.setItem('qrguard.theme', 'light')
    function Probe() {
      return <Text>{useTheme().theme}</Text>
    }
    await render(
      <ThemeProvider>
        <Probe />
      </ThemeProvider>,
    )
    expect(await screen.findByText('light')).toBeOnTheScreen()
  })
})
