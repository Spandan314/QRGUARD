import { Alert, Platform } from 'react-native'

/**
 * Asks the user to confirm a destructive action. Native: a system alert. Web build: the browser's
 * confirm() (React Native Web's Alert.alert shows nothing).
 */
export function confirmAction(title: string, message: string, confirmLabel: string, onConfirm: () => void): void {
  if (Platform.OS === 'web') {
    if (typeof window !== 'undefined' && window.confirm(`${title}\n\n${message}`)) onConfirm()
    return
  }
  Alert.alert(title, message, [
    { text: 'Cancel', style: 'cancel' },
    { text: confirmLabel, style: 'destructive', onPress: onConfirm },
  ])
}
