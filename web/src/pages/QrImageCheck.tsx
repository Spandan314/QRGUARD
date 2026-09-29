import { useState, type FormEvent } from 'react'
import { buttonClass, CheckPage } from '../components/CheckPage'
import { FileDropzone } from '../components/FileDropzone'
import { useAnalysis } from '../hooks/useAnalysis'
import { api } from '../services/api'

export default function QrImageCheck() {
  const [file, setFile] = useState<File | null>(null)
  const { state, run } = useAnalysis(api.analyzeQrImage)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (file) void run(file)
  }

  return (
    <CheckPage
      title="Check a QR code image"
      intro={
        <>
          Upload a photo or screenshot of a QR code. QRGUARD reads it and checks what it would do (open a link,
          make a UPI payment, join a Wi-Fi network…). <strong>Scanning a UPI QR code always sends money – it never
          receives it.</strong>
        </>
      }
      state={state}
    >
      <form onSubmit={submit} className="space-y-3">
        <FileDropzone label="Image with a QR code" file={file} onFile={setFile} disabled={state.status === 'loading'} />
        <button type="submit" className={buttonClass} disabled={!file || state.status === 'loading'}>
          Check QR code
        </button>
      </form>
    </CheckPage>
  )
}
