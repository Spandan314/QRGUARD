import { Tabs } from 'expo-router'
import { Text } from 'react-native'
import { colors } from '../../constants/theme'
import { useAuth } from '../../context/AuthContext'

const icon = (glyph: string) =>
  function TabIcon() {
    return <Text style={{ fontSize: 20 }}>{glyph}</Text>
  }

export default function TabsLayout() {
  const { user } = useAuth()
  return (
    <Tabs screenOptions={{ tabBarActiveTintColor: colors.brand, headerTitleStyle: { fontWeight: '700' } }}>
      <Tabs.Screen name="index" options={{ title: 'QRGUARD', tabBarLabel: 'Home', tabBarIcon: icon('🛡️') }} />
      <Tabs.Screen name="history" options={{ title: 'My history', tabBarLabel: 'History', tabBarIcon: icon('🕘') }} />
      <Tabs.Screen
        name="settings"
        options={{ title: 'Account & about', tabBarLabel: user ? 'Account' : 'Sign in', tabBarIcon: icon('👤') }}
      />
    </Tabs>
  )
}
