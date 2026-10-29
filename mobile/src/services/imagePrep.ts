// Prepares a gallery image for upload. Phone screenshots and photos are often several megabytes
// and thousands of pixels; sending them unchanged is slow on mobile data, can exceed the server's
// 5 MB limit (the upload is then cut off, which Android reports as a network failure) and makes
// OCR slower. So the image is re-encoded as JPEG with its longest side limited to MAX_SIDE, which
// keeps small text readable (1600 px is more than a phone screenshot's width). A smaller upload
// also needs less memory and time on the free server. Re-encoding drops metadata such as GPS location.
import { ImageManipulator, SaveFormat } from 'expo-image-manipulator'
import type { PickedImage } from './api'

export const MAX_SIDE = 1600
export const JPEG_QUALITY = 0.85

export interface SourceImage {
  uri: string
  width: number
  height: number
}

/** New size with the longest side at most MAX_SIDE (null = keep the size). */
export function targetSize(width: number, height: number): { width: number } | { height: number } | null {
  if (!width || !height || Math.max(width, height) <= MAX_SIDE) return null
  return width >= height ? { width: MAX_SIDE } : { height: MAX_SIDE }
}

export async function prepareImage(source: SourceImage): Promise<PickedImage> {
  const context = ImageManipulator.manipulate(source.uri)
  const size = targetSize(source.width, source.height)
  if (size) context.resize(size)
  const rendered = await context.renderAsync()
  const saved = await rendered.saveAsync({ compress: JPEG_QUALITY, format: SaveFormat.JPEG })
  return { uri: saved.uri, name: 'image.jpg', mimeType: 'image/jpeg' }
}
