import * as Clipboard from 'expo-clipboard'
import { Alert, Linking, Text, View } from 'react-native'
import type { VerdictLabel } from '../types/api'
import { hasUserInfo, hostOf, linkAction } from '../utils/links'
import { ActionButton, styles as ui } from './ui'

/**
 * The ONLY place where the app opens an external link (lint forbids Linking elsewhere). It opens
 * exactly `url` (the checked address), never a corrected or "similar" one.
 * SAFE: confirm. UNVERIFIED: confirm with a caution. SUSPICIOUS: warning. MALICIOUS: copy only,
 * opening needs a second explicit confirmation. Non-web schemes and user@host links never open.
 */
export function OpenLinkGuard({
  url,
  verdict,
  finalUrl,
}: {
  url: string
  verdict: VerdictLabel
  /** Where the link was seen to redirect to, if that is a different address. */
  finalUrl?: string | null
}) {
  const action = linkAction(url, verdict)
  const host = hostOf(url)
  const redirectNote = finalUrl && finalUrl !== url ? `\n\nThis link redirects to:\n${finalUrl}` : ''

  const copy = async () => {
    await Clipboard.setStringAsync(url)
    Alert.alert('Copied', 'The link was copied. Paste it only if you are sure it is genuine.')
  }
  const open = () => {
    Linking.openURL(url).catch(() => Alert.alert('Could not open the link', 'No app on this phone can open it.'))
  }

  const onOpen = () => {
    const where = `You are about to open ${host}:\n${url}${redirectNote}`
    if (action === 'confirm') {
      Alert.alert('Open this link?', where, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Open', onPress: open },
      ])
    } else if (action === 'caution') {
      Alert.alert('Open an unverified link?', `${where}\n\nQRGUARD could not verify this website. Do not enter passwords, OTPs or payment details unless you are sure it is genuine.`, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Open', onPress: open },
      ])
    } else if (action === 'warn') {
      Alert.alert('This link looks suspicious', `${where}\n\nOnly continue if you trust the sender.`, [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Open anyway', style: 'destructive', onPress: open },
      ])
    } else if (action === 'copy-only') {
      Alert.alert('Dangerous link', `${where}\n\nQRGUARD strongly advises not to open it.`, [
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
          variant={action === 'confirm' || action === 'caution' ? 'primary' : 'danger'}
          onPress={onOpen}
        />
      ) : (
        <Text style={ui.small} testID="never-open-reason">
          {hasUserInfo(url)
            ? 'This link hides its real address behind a name and "@", a common trick. QRGUARD does not open it.'
            : 'This is not a normal web link, so QRGUARD does not open it.'}
        </Text>
      )}
    </View>
  )
}
