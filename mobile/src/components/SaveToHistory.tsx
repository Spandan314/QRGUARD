import { useRouter } from 'expo-router'
import { useState } from 'react'
import { Pressable, Switch, Text, View } from 'react-native'
import { useOptionalAuth } from '../context/AuthContext'
import { colors } from '../constants/theme'
import { styles as ui } from './ui'

/** Opt-in "save to my history" choice; defaults to the user's setting. */
export function useSaveOption() {
  const auth = useOptionalAuth()
  const [choice, setChoice] = useState<boolean | null>(null)
  const available = Boolean(auth?.user && auth.profile)
  const save = available && (choice ?? auth?.profile?.save_history ?? false)
  return { save, available, setSave: setChoice }
}

export function SaveToHistory({ option }: { option: ReturnType<typeof useSaveOption> }) {
  const auth = useOptionalAuth()
  const router = useRouter()
  if (!option.available) {
    if (!auth || auth.client.mode === 'off' || auth.user) return null
    return (
      <Pressable accessibilityRole="link" onPress={() => router.push('/settings')}>
        <Text style={ui.small}>
          <Text style={{ color: colors.brand, fontWeight: '600' }}>Sign in</Text> to keep a private history (verdicts only).
        </Text>
      </Pressable>
    )
  }
  return (
    <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
      <Switch
        accessibilityLabel="Save the result to my history"
        value={option.save}
        onValueChange={(value) => option.setSave(value)}
      />
      <Text style={[ui.small, { flex: 1 }]}>Save the result to my history (only the verdict, never the content)</Text>
    </View>
  )
}
