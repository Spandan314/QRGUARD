import { useState } from 'react'
import { Pressable, Text, TextInput, View } from 'react-native'
import { colors, MIN_TOUCH } from '../constants/theme'
import { useOptionalAuth } from '../context/AuthContext'
import { api, ApiError } from '../services/api'
import type { ReportKind } from '../types/api'
import { ActionButton, styles as ui } from './ui'

const KINDS: { value: ReportKind; label: string }[] = [
  { value: 'false_positive', label: 'It is genuine (wrongly flagged)' },
  { value: 'false_negative', label: 'It is a scam (missed)' },
  { value: 'scam', label: 'Report as a scam' },
]

/** Lets a signed-in user tell the team a result is wrong (only the verdict is linked). */
export function ReportForm({ scanId }: { scanId?: string | undefined }) {
  const auth = useOptionalAuth()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<ReportKind>('false_positive')
  const [note, setNote] = useState('')
  const [status, setStatus] = useState<'idle' | 'sending' | 'sent' | string>('idle')

  if (!auth?.user || !auth.profile) return null
  if (status === 'sent') return <Text style={ui.body}>Thank you – your report was sent to the QRGUARD team.</Text>
  if (!open) return <ActionButton label="Is this result wrong? Report it" variant="secondary" onPress={() => setOpen(true)} />

  async function send() {
    setStatus('sending')
    try {
      await api.report(kind, note.trim(), scanId)
      setStatus('sent')
    } catch (error) {
      setStatus(error instanceof ApiError ? error.message : 'The report could not be sent.')
    }
  }

  return (
    <View style={{ gap: 8 }} testID="report-form">
      <Text style={ui.label}>What is wrong?</Text>
      {KINDS.map((option) => (
        <Pressable
          key={option.value}
          accessibilityRole="radio"
          accessibilityLabel={option.label}
          accessibilityState={{ checked: kind === option.value }}
          onPress={() => setKind(option.value)}
          style={{ minHeight: MIN_TOUCH, justifyContent: 'center' }}
        >
          <Text style={{ color: kind === option.value ? colors.brand : colors.text, fontWeight: kind === option.value ? '700' : '400' }}>
            {kind === option.value ? '◉ ' : '○ '}
            {option.label}
          </Text>
        </Pressable>
      ))}
      <TextInput
        accessibilityLabel="Note (optional)"
        style={[ui.input, { minHeight: 70, textAlignVertical: 'top' }]}
        value={note}
        onChangeText={setNote}
        maxLength={280}
        multiline
        placeholder="Optional note (no personal data such as account numbers or OTPs)"
      />
      <ActionButton label="Send report" loading={status === 'sending'} onPress={() => void send()} />
      <ActionButton label="Cancel" variant="secondary" onPress={() => setOpen(false)} />
      {status !== 'idle' && status !== 'sending' ? (
        <Text style={ui.errorText} accessibilityRole="alert">
          {status}
        </Text>
      ) : null}
    </View>
  )
}
