import { CameraView, useCameraPermissions, type BarcodeScanningResult } from 'expo-camera'
import { SaveToHistory, useSaveOption } from '../../components/SaveToHistory'
import { useFocusEffect } from 'expo-router'
import { useCallback, useRef, useState } from 'react'
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { useAnalysis } from '../../hooks/useAnalysis'
import { api } from '../../services/api'

/**
 * Scans once, sends the decoded text to the backend and shows the result. The QR code is NEVER
 * opened, paid or connected to by the app.
 */
export default function CameraScan() {
  const [permission, requestPermission] = useCameraPermissions()
  const { loading, error, run } = useAnalysis(api.analyzeQrContent)
  const saveOption = useSaveOption()
  const scanned = useRef(false)
  const [paused, setPaused] = useState(false)

  // Scanning resumes when the user comes back to this screen.
  useFocusEffect(
    useCallback(() => {
      scanned.current = false
      setPaused(false)
    }, []),
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

  if (!permission) return <ActivityIndicator style={{ marginTop: 40 }} />
  if (!permission.granted) {
    return (
      <Screen title="Camera permission" intro="QRGUARD needs the camera only to scan QR codes. Nothing is recorded or stored.">
        <ActionButton label="Allow camera" onPress={() => void requestPermission()} />
        {!permission.canAskAgain ? (
          <Text style={ui.small}>Camera access was denied. You can allow it in the phone settings.</Text>
        ) : null}
      </Screen>
    )
  }

  return (
    <View style={{ flex: 1 }}>
      <CameraView
        style={StyleSheet.absoluteFill}
        facing="back"
        barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={paused ? undefined : onScanned}
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
