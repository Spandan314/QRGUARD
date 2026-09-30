import * as ImagePicker from 'expo-image-picker'
import { useState } from 'react'
import { Image, Text, View } from 'react-native'
import { MAX_UPLOAD_BYTES } from '../constants/config'
import type { PickedImage } from '../services/api'
import { ActionButton, styles as ui } from './ui'

const ACCEPTED = ['image/png', 'image/jpeg', 'image/webp']

/** Picks one image from the gallery. Type and size checks are a convenience; the server re-checks. */
export function ImagePickerField({
  image,
  onImage,
  label,
}: {
  image: PickedImage | null
  onImage: (image: PickedImage | null) => void
  label: string
}) {
  const [problem, setProblem] = useState<string | null>(null)

  async function pick() {
    const result = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 1, allowsEditing: false })
    if (result.canceled) return
    const asset = result.assets[0]
    if (!asset) return
    const mimeType = asset.mimeType ?? 'image/jpeg'
    if (!ACCEPTED.includes(mimeType)) {
      setProblem('Please choose a PNG, JPEG or WEBP image.')
      onImage(null)
      return
    }
    if (asset.fileSize && asset.fileSize > MAX_UPLOAD_BYTES) {
      setProblem('The image is larger than 5 MB.')
      onImage(null)
      return
    }
    setProblem(null)
    onImage({ uri: asset.uri, name: asset.fileName ?? `image.${mimeType.split('/')[1]}`, mimeType })
  }

  return (
    <View style={{ gap: 8 }}>
      <ActionButton label={image ? 'Choose a different image' : label} variant="secondary" onPress={() => void pick()} />
      {image ? (
        <Image
          source={{ uri: image.uri }}
          style={{ width: '100%', height: 220, resizeMode: 'contain' }}
          accessibilityLabel="Selected image"
        />
      ) : null}
      {problem ? (
        <Text style={ui.errorText} accessibilityRole="alert">
          {problem}
        </Text>
      ) : null}
    </View>
  )
}
