import { useCallback, useState, type FormEvent } from 'react'
import { buttonClass, CheckPage } from '../components/CheckPage'
import { FileDropzone } from '../components/FileDropzone'
import { QrCameraScanner } from '../components/QrCameraScanner'
import { SaveToHistory, useSaveOption } from '../components/SaveToHistory'
import { useAnalysis } from '../hooks/useAnalysis'
import { api } from '../services/api'

type Mode = 'image' | 'camera'

export default function QrImageCheck() {
  const [mode, setMode] = useState<Mode>('image')
  const [file, setFile] = useState<File | null>(null)
  const image = useAnalysis(api.analyzeQrImage)
  const camera = useAnalysis(api.analyzeQrContent)
  const saveOption = useSaveOption()
  const [scanned, setScanned] = useState(false)
  const state = mode === 'image' ? image.state : camera.state

  const { run: runCamera } = camera
  const save = saveOption.save
  const onCode = useCallback(
    (content: string) => {
      setScanned(true)
      void runCamera(content, { save })
    },
    [runCamera, save],
  )

  function submit(event: FormEvent) {
    event.preventDefault()
    if (file) void image.run(file, { save: saveOption.save })
  }

  return (
    <CheckPage
      title="Check a QR code"
      intro={
        <>
          Scan a QR code with your camera or upload a photo of it. QRGUARD reads it and checks what it would do
          (open a link, make a UPI payment, join a Wi-Fi network…) – it never opens it.{' '}
          <strong>Scanning a UPI QR code always sends money – it never receives it.</strong>
        </>
      }
      state={state}
    >
      <div className="mb-4 flex gap-2" role="tablist" aria-label="How to read the QR code">
        {(['image', 'camera'] as const).map((option) => (
          <button
            key={option}
            type="button"
            role="tab"
            aria-selected={mode === option}
            onClick={() => {
              setMode(option)
              setScanned(false)
            }}
            className={`min-h-11 rounded-lg px-4 font-medium ${
              mode === option ? 'bg-teal-700 text-white' : 'border border-slate-300 dark:border-slate-600'
            }`}
          >
            {option === 'image' ? 'Upload an image' : 'Use the camera'}
          </button>
        ))}
      </div>
      {mode === 'image' ? (
        <form onSubmit={submit} className="space-y-3">
          <FileDropzone label="Image with a QR code" file={file} onFile={setFile} disabled={state.status === 'loading'} />
          <SaveToHistory option={saveOption} />
          <button type="submit" className={buttonClass} disabled={!file || state.status === 'loading'}>
            Check QR code
          </button>
        </form>
      ) : (
        <div className="space-y-3">
          <SaveToHistory option={saveOption} />
          <QrCameraScanner onCode={onCode} paused={scanned} />
          {scanned && state.status !== 'loading' ? (
            <button type="button" className={buttonClass} onClick={() => setScanned(false)}>
              Scan another code
            </button>
          ) : null}
        </div>
      )}
    </CheckPage>
  )
}
