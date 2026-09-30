import { useState } from 'react'
import { SaveToHistory, useSaveOption } from '../../components/SaveToHistory'
import { Text, TextInput } from 'react-native'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { MAX_MESSAGE_CHARS } from '../../constants/config'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api } from '../../services/api'

export default function MessageCheck() {
  const [text, setText] = useState('')
  const { loading, error, run } = useAnalysis(api.analyzeMessage)
  const saveOption = useSaveOption()

  return (
    <Screen intro="Paste an SMS, WhatsApp or e-mail message. Links inside it are checked too.">
      <Card>
        <Text style={ui.label}>Message text</Text>
        <TextInput
          accessibilityLabel="Message text"
          style={[ui.input, { minHeight: 160, textAlignVertical: 'top' }]}
          value={text}
          onChangeText={setText}
          placeholder="Dear customer, your account will be blocked today…"
          multiline
          maxLength={MAX_MESSAGE_CHARS}
        />
        <Text style={ui.small}>
          {text.length} / {MAX_MESSAGE_CHARS} · We do not store message text.
        </Text>
        <SaveToHistory option={saveOption} />
        <ActionButton label="Check message" loading={loading} disabled={!text.trim()} onPress={() => void run(text, { save: saveOption.save })} />
      </Card>
      {error ? <ErrorBanner error={error} /> : null}
    </Screen>
  )
}
