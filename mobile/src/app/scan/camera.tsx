import { CameraView, useCameraPermissions, type BarcodeScanningResult } from 'expo-camera'
import { useFocusEffect, useRouter } from 'expo-router'
import { useCallback, useEffect, useRef, useState } from 'react'
import { ActivityIndicator, AppState, StyleSheet, Text, View } from 'react-native'
import { SaveToHistory, useSaveOption } from '../../components/SaveToHistory'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api } from '../../services/api'
import { openAppSettings } from '../../utils/systemSettings'

/** What the permission screen should offer (exported for tests). */
export type CameraAccess = 'loading' | 'granted' | 'ask' | 'ask-again' | 'blocked'

export function cameraAccess(permission: { granted: boolean; canAskAgain: boolean; status: string } | null): CameraAccess {
  if (!permission) return 'loading'
  if (permission.granted) return 'granted'
  if (permission.status === 'undetermined') return 'ask'
  // Android stops showing the system dialog after repeated denials: asking again would do nothing,
  // so the user is sent to the app's settings instead.
  return permission.canAskAgain ? 'ask-again' : 'blocked'
}

/**
 * Scans once, sends the decoded text to the backend and shows the result. The QR code is NEVER
 * opened, paid or connected to by the app. Only the camera permission is used.
 */
export default function CameraScan() {
  const router = useRouter()
  const [permission, requestPermission, getPermission] = useCameraPermissions()
  const { loading, error, run } = useAnalysis(api.analyzeQrContent)
  const saveOption = useSaveOption()
  const scanned = useRef(false)
  const [paused, setPaused] = useState(false)
  const [cameraError, setCameraError] = useState<string | null>(null)
  const [cameraKey, setCameraKey] = useState(0)
  const access = cameraAccess(permission)

  // Coming back from the system settings: read the permission again so scanning starts at once.
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (state) => {
      if (state === 'active') void getPermission()
    })
    return () => subscription.remove()
  }, [getPermission])

  // Scanning resumes when the user comes back to this screen.
  useFocusEffect(
    useCallback(() => {
      scanned.current = false
      setPaused(false)
      void getPermission()
    }, [getPermission]),
  )

  const onScanned = useCallback(
    (event: BarcodeScanningResult) => {
      if (scanned.current || !event.data) return
      scanned.current = true // debounce: the camera reports the same code many times per second
      setPaused(true)
      void run(event.data.slice(0, 4096), { save: saveOption.save }).then((ok) => {
        if (!ok) {
          scanned.current = false
          setPaused(false)
        }
      })
    },
    [run, saveOption.save],
  )

  const alternatives = (
    <Card>
      <Text style={ui.body}>You can also check a QR code without the camera:</Text>
      <ActionButton label="Choose an image instead" variant="secondary" onPress={() => router.replace('/check/image')} />
      <ActionButton label="Type or paste the link" variant="secondary" onPress={() => router.replace('/check/url')} />
    </Card>
  )

  if (access === 'loading') {
    return (
      <Screen>
        <ActivityIndicator style={{ marginTop: 40 }} accessibilityLabel="Checking camera permission" />
      </Screen>
    )
  }

  if (access !== 'granted') {
    return (
      <Screen title="Camera permission" intro="QRGUARD uses the camera only to scan QR codes. Nothing is recorded, saved or sent except the decoded QR text.">
        <Card>
          {access === 'blocked' ? (
            <>
              <Text style={ui.body} testID="camera-blocked">
                Camera access is turned off for QRGUARD. To scan QR codes, open the settings, choose
                Permissions → Camera → Allow, then come back here.
              </Text>
              <ActionButton
                label="Open settings"
                onPress={() =>
                  void openAppSettings().then((opened) => {
                    if (!opened) setCameraError('The settings could not be opened. Open them from the phone menu: Apps → QRGUARD → Permissions.')
                  })
                }
              />
              <ActionButton label="I allowed it – check again" variant="secondary" onPress={() => void getPermission()} />
            </>
          ) : (
            <>
              {access === 'ask-again' ? (
                <Text style={ui.body} testID="camera-denied">
                  Camera access was denied. Without it QRGUARD cannot scan QR codes.
                </Text>
              ) : null}
              <ActionButton label="Allow camera" onPress={() => void requestPermission()} />
            </>
          )}
          {cameraError ? (
            <Text style={ui.errorText} accessibilityRole="alert">
              {cameraError}
            </Text>
          ) : null}
        </Card>
        {alternatives}
      </Screen>
    )
  }

  if (cameraError) {
    return (
      <Screen title="Camera problem">
        <Card>
          <Text style={ui.errorText} accessibilityRole="alert" testID="camera-error">
            {cameraError}
          </Text>
          <ActionButton
            label="Try again"
            onPress={() => {
              setCameraError(null)
              setCameraKey((key) => key + 1)
            }}
          />
        </Card>
        {alternatives}
      </Screen>
    )
  }

  return (
    <View style={{ flex: 1 }}>
      <CameraView
        key={cameraKey}
        style={StyleSheet.absoluteFill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={paused ? undefined : onScanned}
        onMountError={() => setCameraError('The camera could not be started. Close other apps that use the camera and try again.')}
      />
      <View style={styles.overlay} pointerEvents="box-none">
        <View style={styles.frame} />
        <Card>
          <SaveToHistory option={saveOption} />
          {loading ? (
            <Text style={ui.body}>Checking the QR code…</Text>
          ) : (
            <Text style={ui.body}>Point the camera at a QR code. It will be checked, never opened.</Text>
          )}
          {error ? <ErrorBanner error={error} /> : null}
        </Card>
      </View>
    </View>
  )
}

const styles = StyleSheet.create({
  overlay: { flex: 1, justifyContent: 'space-between', padding: 16, paddingBottom: 32 },
  frame: { alignSelf: 'center', marginTop: 80, width: 240, height: 240, borderWidth: 3, borderColor: '#fff', borderRadius: 16 },
})
