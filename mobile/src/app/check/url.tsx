import * as Clipboard from 'expo-clipboard'
import { SaveToHistory, useSaveOption } from '../../components/SaveToHistory'
import { useState } from 'react'
import { Text, TextInput, View } from 'react-native'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { MAX_URL_CHARS } from '../../constants/config'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api } from '../../services/api'

export default function UrlCheck() {
  const [url, setUrl] = useState('')
  const { loading, error, run } = useAnalysis(api.analyzeUrl)
  const saveOption = useSaveOption()

  return (
    <Screen intro="Paste a link you received. QRGUARD examines it without opening the page for you.">
      <Card>
        <Text style={ui.label} nativeID="url-label">
          Link
        </Text>
        <TextInput
          accessibilityLabelledBy="url-label"
          accessibilityLabel="Link"
          style={ui.input}
          value={url}
          onChangeText={setUrl}
          placeholder="https://example.com/offer"
          autoCapitalize="none"
          autoCorrect={false}
          keyboardType="url"
          maxLength={MAX_URL_CHARS}
        />
        <SaveToHistory option={saveOption} />
        <View style={{ flexDirection: 'row', gap: 8 }}>
          <View style={{ flex: 1 }}>
            <ActionButton
              label="Paste"
              variant="secondary"
              onPress={() => void Clipboard.getStringAsync().then((text) => setUrl(text.slice(0, MAX_URL_CHARS)))}
            />
          </View>
          <View style={{ flex: 2 }}>
            <ActionButton label="Check link" loading={loading} disabled={!url.trim()} onPress={() => void run(url.trim(), { save: saveOption.save })} />
          </View>
        </View>
      </Card>
      {error ? <ErrorBanner error={error} /> : null}
    </Screen>
  )
}
