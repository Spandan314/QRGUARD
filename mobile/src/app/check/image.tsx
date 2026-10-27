import { useState } from 'react'
import { Text } from 'react-native'
import { ImagePickerField } from '../../components/ImagePickerField'
import { SaveToHistory, useSaveOption } from '../../components/SaveToHistory'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api, type PickedImage } from '../../services/api'

/**
 * One gallery flow for screenshots AND photos of QR codes. The server decodes every QR code in the
 * image and reads its text (OCR), then analyses both: a QR code alone is checked like a scanned
 * one, text like a pasted message. Nothing from the image is stored.
 */
export default function ImageCheck() {
  const [image, setImage] = useState<PickedImage | null>(null)
  const { loading, error, run, retry } = useAnalysis(api.analyzeImage)
  const saveOption = useSaveOption()

  return (
    <Screen intro="Choose a screenshot of a message, or a photo of a QR code. QRGUARD reads any QR code and text in the image and checks them. The image is not stored.">
      <Card>
        <ImagePickerField label="Choose image to check" image={image} onImage={setImage} />
        <Text style={ui.small}>
          Tip: hide or crop out account numbers and balances first. Only the text that matters is needed.
        </Text>
        <SaveToHistory option={saveOption} />
        <ActionButton label={loading ? 'Checking… (can take up to a minute)' : 'Check image'} loading={loading} disabled={!image} onPress={() => image && void run(image, { save: saveOption.save })} />
      </Card>
      {error ? <ErrorBanner error={error} onRetry={image && !loading ? () => void retry() : undefined} /> : null}
    </Screen>
  )
}
