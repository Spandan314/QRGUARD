import { Tabs } from 'expo-router'
import type { ColorValue } from 'react-native'
import { BrandTitle } from '../../components/BrandTitle'
import { TabIcon, type TabIconName } from '../../components/TabIcon'
import { colors } from '../../constants/theme'
import { useAuth } from '../../context/AuthContext'

const icon = (name: TabIconName) =>
  function TabBarIcon({ color, size }: { color: ColorValue; size: number }) {
    return <TabIcon name={name} color={color} size={size} />
  }

export default function TabsLayout() {
  const { user } = useAuth()
  return (
    <Tabs screenOptions={{ tabBarActiveTintColor: colors.brand, headerTitleStyle: { fontWeight: '700' } }}>
      <Tabs.Screen name="index" options={{ title: 'QRGUARD', headerTitle: BrandTitle, tabBarLabel: 'Home', tabBarIcon: icon('home') }} />
      <Tabs.Screen name="history" options={{ title: 'My history', tabBarLabel: 'History', tabBarIcon: icon('history') }} />
      <Tabs.Screen
        name="settings"
        options={{ title: 'Account & about', tabBarLabel: user ? 'Account' : 'Sign in', tabBarIcon: icon('account') }}
      />
    </Tabs>
  )
}
