import * as ImagePicker from 'expo-image-picker'
import { useState } from 'react'
import { ActivityIndicator, Image, Text, View } from 'react-native'
import { MAX_UPLOAD_BYTES } from '../constants/config'
import type { PickedImage } from '../services/api'
import { prepareImage } from '../services/imagePrep'
import { ActionButton, styles as ui } from './ui'

const ACCEPTED = ['image/png', 'image/jpeg', 'image/webp', 'image/heic', 'image/heif']

/**
 * Picks one image from the gallery with the system photo picker (no storage permission needed)
 * and prepares it for upload. Type and size checks are a convenience; the server re-checks.
 */
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
  const [preparing, setPreparing] = useState(false)

  async function pick() {
    let result: ImagePicker.ImagePickerResult
    try {
      result = await ImagePicker.launchImageLibraryAsync({ mediaTypes: ['images'], quality: 1, allowsEditing: false })
    } catch {
      setProblem('The photo gallery could not be opened. Please try again.')
      return
    }
    if (result.canceled) return
    const asset = result.assets[0]
    if (!asset) return
    const mimeType = asset.mimeType ?? 'image/jpeg'
    if (!ACCEPTED.includes(mimeType)) {
      setProblem('Please choose a photo or screenshot (PNG, JPEG, WEBP or HEIC).')
      onImage(null)
      return
    }
    setProblem(null)
    setPreparing(true)
    try {
      onImage(await prepareImage({ uri: asset.uri, width: asset.width, height: asset.height }))
    } catch {
      // Could not re-encode on the phone: send the original if the server can accept it.
      if (mimeType === 'image/heic' || mimeType === 'image/heif' || (asset.fileSize ?? 0) > MAX_UPLOAD_BYTES) {
        setProblem('This image could not be prepared for checking. Please take a new screenshot and try again.')
        onImage(null)
      } else {
        onImage({ uri: asset.uri, name: asset.fileName ?? `image.${mimeType.split('/')[1]}`, mimeType })
      }
    } finally {
      setPreparing(false)
    }
  }

  return (
    <View style={{ gap: 8 }}>
      <ActionButton label={image ? 'Choose a different image' : label} variant="secondary" loading={preparing} onPress={() => void pick()} />
      {preparing ? <ActivityIndicator accessibilityLabel="Preparing the image" /> : null}
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
