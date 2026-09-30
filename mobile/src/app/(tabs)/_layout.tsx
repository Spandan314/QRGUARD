import { Tabs } from 'expo-router'
import { Text } from 'react-native'
import { colors } from '../../constants/theme'

const icon = (glyph: string) =>
  function TabIcon() {
    return <Text style={{ fontSize: 20 }}>{glyph}</Text>
  }

export default function TabsLayout() {
  return (
    <Tabs screenOptions={{ tabBarActiveTintColor: colors.brand, headerTitleStyle: { fontWeight: '700' } }}>
      <Tabs.Screen name="index" options={{ title: 'QRGUARD', tabBarLabel: 'Home', tabBarIcon: icon('🛡️') }} />
      <Tabs.Screen name="settings" options={{ title: 'About & settings', tabBarLabel: 'About', tabBarIcon: icon('ℹ️') }} />
    </Tabs>
  )
}
