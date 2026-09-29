import * as FileSystem from 'expo-file-system'
import * as Sharing from 'expo-sharing'
import { useRef, useState } from 'react'
import { Pressable, Switch, Text, TextInput, View } from 'react-native'
import QRCode from 'react-native-qrcode-svg'
import { ActionButton, Card, Screen, styles as ui } from '../components/ui'
import { colors, MIN_TOUCH } from '../constants/theme'
import { buildPayload, PayloadError, type QrInput, type QrKind, type WifiSecurity } from '../utils/qrPayload'

const KINDS: { value: QrKind; label: string }[] = [
  { value: 'url', label: 'Link' },
  { value: 'text', label: 'Text' },
  { value: 'wifi', label: 'Wi-Fi' },
  { value: 'email', label: 'E-mail' },
  { value: 'phone', label: 'Phone' },
]
const SECURITY: { value: WifiSecurity; label: string }[] = [
  { value: 'WPA', label: 'WPA/WPA2' },
  { value: 'WPA3', label: 'WPA3' },
  { value: 'WEP', label: 'WEP' },
  { value: 'nopass', label: 'Open' },
]

interface QrRef {
  toDataURL: (callback: (base64: string) => void) => void
}

function Field(props: { label: string; value: string | undefined; onChange: (v: string) => void; secure?: boolean; multiline?: boolean }) {
  return (
    <View style={{ gap: 4 }}>
      <Text style={ui.label}>{props.label}</Text>
      <TextInput
        accessibilityLabel={props.label}
        style={[ui.input, props.multiline && { minHeight: 90, textAlignVertical: 'top' }]}
        value={props.value ?? ''}
        onChangeText={props.onChange}
        secureTextEntry={props.secure ?? false}
        multiline={props.multiline ?? false}
        autoCapitalize="none"
        autoCorrect={false}
      />
    </View>
  )
}

function Chips<T extends string>({ options, value, onChange }: { options: { value: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }} accessibilityRole="radiogroup">
      {options.map((option) => (
        <Pressable
          key={option.value}
          accessibilityRole="radio"
          accessibilityLabel={option.label}
          accessibilityState={{ checked: value === option.value }}
          onPress={() => onChange(option.value)}
          style={{
            minHeight: MIN_TOUCH,
            justifyContent: 'center',
            paddingHorizontal: 14,
            borderRadius: 999,
            borderWidth: 1,
            borderColor: colors.utility,
            backgroundColor: value === option.value ? colors.utility : '#fff',
          }}
        >
          <Text style={{ color: value === option.value ? '#fff' : colors.utility, fontWeight: '600' }}>{option.label}</Text>
        </Pressable>
      ))}
    </View>
  )
}

/** Utility screen, visually separate from the checks. The code is made on the phone. */
export default function Generate() {
  const [kind, setKind] = useState<QrKind>('url')
  const [input, setInput] = useState<QrInput>({ security: 'WPA' })
  const [payload, setPayload] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const qrRef = useRef<QrRef | null>(null)
  const set = (key: keyof QrInput) => (value: string) => setInput((current) => ({ ...current, [key]: value }))

  function create() {
    try {
      setPayload(buildPayload(kind, input))
      setError(null)
    } catch (caught) {
      setPayload(null)
      setError(caught instanceof PayloadError ? caught.message : 'Could not create the QR code.')
    }
  }

  function share() {
    qrRef.current?.toDataURL((base64) => {
      const file = new FileSystem.File(FileSystem.Paths.cache, 'qrguard-qr.png')
      file.write(base64, { encoding: 'base64' })
      void Sharing.isAvailableAsync().then((available) => {
        if (available) void Sharing.shareAsync(file.uri, { mimeType: 'image/png', dialogTitle: 'Share QR code' })
      })
    })
  }

  return (
    <Screen intro="Utility – separate from the security checks. The code is created on your phone; nothing you type (including Wi-Fi passwords) is sent to QRGUARD.">
      <Card>
        <Chips
          options={KINDS}
          value={kind}
          onChange={(value) => {
            setKind(value)
            setPayload(null)
            setError(null)
          }}
        />
        {kind === 'url' ? <Field label="Link to encode" value={input.url} onChange={set('url')} /> : null}
        {kind === 'text' ? <Field label="Text to encode" value={input.text} onChange={set('text')} multiline /> : null}
        {kind === 'wifi' ? (
          <>
            <Field label="Network name (SSID)" value={input.ssid} onChange={set('ssid')} />
            <Chips options={SECURITY} value={input.security ?? 'WPA'} onChange={(security) => setInput((c) => ({ ...c, security }))} />
            {input.security !== 'nopass' ? <Field label="Password" value={input.password} onChange={set('password')} secure /> : null}
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
              <Switch
                accessibilityLabel="Hidden network"
                value={input.hidden ?? false}
                onValueChange={(hidden) => setInput((c) => ({ ...c, hidden }))}
              />
              <Text style={ui.body}>Hidden network</Text>
            </View>
          </>
        ) : null}
        {kind === 'email' ? (
          <>
            <Field label="E-mail address" value={input.to} onChange={set('to')} />
            <Field label="Subject (optional)" value={input.subject} onChange={set('subject')} />
            <Field label="Message (optional)" value={input.body} onChange={set('body')} multiline />
          </>
        ) : null}
        {kind === 'phone' ? <Field label="Phone number" value={input.number} onChange={set('number')} /> : null}
        <ActionButton label="Create QR code" onPress={create} />
        {error ? (
          <Text style={ui.errorText} accessibilityRole="alert">
            {error}
          </Text>
        ) : null}
      </Card>
      {payload ? (
        <Card style={{ alignItems: 'center' }}>
          <View testID="generated-qr" accessibilityLabel="Generated QR code">
            <QRCode value={payload} size={240} ecl="M" quietZone={16} getRef={(ref: QrRef) => (qrRef.current = ref)} />
          </View>
          <ActionButton label="Share or save" variant="secondary" onPress={share} />
        </Card>
      ) : null}
    </Screen>
  )
}
