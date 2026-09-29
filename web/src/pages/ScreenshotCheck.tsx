import { useState, type FormEvent } from 'react'
import { buttonClass, CheckPage } from '../components/CheckPage'
import { FileDropzone } from '../components/FileDropzone'
import { SaveToHistory, useSaveOption } from '../components/SaveToHistory'
import { useAnalysis } from '../hooks/useAnalysis'
import { api } from '../services/api'

export default function ScreenshotCheck() {
  const [file, setFile] = useState<File | null>(null)
  const { state, run } = useAnalysis(api.analyzeScreenshot)
  const saveOption = useSaveOption()

  function submit(event: FormEvent) {
    event.preventDefault()
    if (file) void run(file, { save: saveOption.save })
  }

  return (
    <CheckPage
      title="Check a screenshot"
      intro="Upload a screenshot of a suspicious message. The text (and any QR code) is read and checked. The image is not stored."
      state={state}
    >
      <form onSubmit={submit} className="space-y-3">
        <FileDropzone label="Screenshot of the message" file={file} onFile={setFile} disabled={state.status === 'loading'} />
        <SaveToHistory option={saveOption} />
        <button type="submit" className={buttonClass} disabled={!file || state.status === 'loading'}>
          Check screenshot
        </button>
      </form>
    </CheckPage>
  )
}
