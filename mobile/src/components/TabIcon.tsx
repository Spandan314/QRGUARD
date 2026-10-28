import type { ColorValue } from 'react-native'
import Svg, { Path } from 'react-native-svg'

// Line icons for the tab bar, drawn in the tab's tint colour so the active tab is clear
// (emoji ignore the tint and look different on every phone).
const PATHS = {
  home: 'M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z',
  history: 'M12 7v5l3 2M3.05 11a9 9 0 1 1 .5 4M3 4v7h7',
  account: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
} as const

export type TabIconName = keyof typeof PATHS

export function TabIcon({ name, color, size }: { name: TabIconName; color: ColorValue; size: number }) {
  return (
    <Svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round">
      <Path d={PATHS[name]} />
    </Svg>
  )
}
