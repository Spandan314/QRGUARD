import * as Clipboard from 'expo-clipboard'
import { Alert, Linking, View } from 'react-native'
import type { RiskLevel } from '../types/api'
import { linkAction } from '../utils/links'
import { ActionButton } from './ui'

/**
 * The ONLY place where the app opens an external link (lint forbids Linking elsewhere).
 * SAFE: confirm with the full URL. SUSPICIOUS: warning dialog. MALICIOUS: copy only, opening
 * needs a second explicit confirmation. intent:, javascript:, data:, file: … are never opened.
 */
export function OpenLinkGuard({ url, level }: { url: string; level: RiskLevel }) {
  const action = linkAction(url, level)

  const copy = async () => {
    await Clipboard.setStringAsync(url)
    Alert.alert('Copied', 'The link was copied. Paste it only if you are sure it is genuine.')
  }
  const open = () => void Linking.openURL(url)

  const onOpen = () => {
    if (action === 'confirm') {
      Alert.alert('Open this link?', url, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Open', onPress: open },
      ])
    } else if (action === 'warn') {
      Alert.alert('This link looks suspicious', `${url}\n\nOnly continue if you trust the sender.`, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Open anyway', style: 'destructive', onPress: open },
      ])
    } else if (action === 'copy-only') {
      Alert.alert('Dangerous link', `${url}\n\nQRGUARD strongly advises not to open it.`, [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'I understand the risk',
          style: 'destructive',
          onPress: () =>
            Alert.alert('Are you absolutely sure?', 'This link is very likely a scam or an attack.', [
              { text: 'No, go back', style: 'cancel' },
              { text: 'Open', style: 'destructive', onPress: open },
            ]),
        },
      ])
    }
  }

  return (
    <View style={{ gap: 8 }} testID="open-link-guard">
      <ActionButton label="Copy link" variant="secondary" onPress={() => void copy()} />
      {action !== 'never' ? (
        <ActionButton
          label={action === 'copy-only' ? 'Open link (not recommended)' : 'Open link'}
          variant={action === 'confirm' ? 'primary' : 'danger'}
          onPress={onOpen}
        />
      ) : null}
    </View>
  )
}
