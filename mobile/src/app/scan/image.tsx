import { useState } from 'react'
import { ImagePickerField } from '../../components/ImagePickerField'
import { ActionButton, Card, ErrorBanner, Screen } from '../../components/ui'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api, type PickedImage } from '../../services/api'

export default function QrImageCheck() {
  const [image, setImage] = useState<PickedImage | null>(null)
  const { loading, error, run } = useAnalysis(api.analyzeQrImage)

  return (
    <Screen intro="Choose a photo or screenshot of a QR code. QRGUARD reads it and explains what it would do.">
      <Card>
        <ImagePickerField label="Choose an image" image={image} onImage={setImage} />
        <ActionButton label="Check QR code" loading={loading} disabled={!image} onPress={() => image && void run(image)} />
      </Card>
      {error ? <ErrorBanner error={error} /> : null}
    </Screen>
  )
}
