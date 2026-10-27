// Opens this app's page in the phone's system settings (e.g. to allow the camera after it was
// denied permanently). The only other use of Linking besides OpenLinkGuard; it opens no URL.
import { Linking } from 'react-native'

export async function openAppSettings(): Promise<boolean> {
  try {
    await Linking.openSettings()
    return true
  } catch {
    return false
  }
}
