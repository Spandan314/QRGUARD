import { useState } from 'react'
import { ImagePickerField } from '../../components/ImagePickerField'
import { ActionButton, Card, ErrorBanner, Screen } from '../../components/ui'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api, type PickedImage } from '../../services/api'

export default function ScreenshotCheck() {
  const [image, setImage] = useState<PickedImage | null>(null)
  const { loading, error, run } = useAnalysis(api.analyzeScreenshot)

  return (
    <Screen intro="Choose a screenshot of a suspicious message. The text and any QR code are read and checked. The image is not stored.">
      <Card>
        <ImagePickerField label="Choose a screenshot" image={image} onImage={setImage} />
        <ActionButton label="Check screenshot" loading={loading} disabled={!image} onPress={() => image && void run(image)} />
      </Card>
      {error ? <ErrorBanner error={error} /> : null}
    </Screen>
  )
}
