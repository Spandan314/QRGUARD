import { useState, type FormEvent } from 'react'
import { buttonClass, CheckPage, inputClass } from '../components/CheckPage'
import { useAnalysis } from '../hooks/useAnalysis'
import { api } from '../services/api'

export default function UrlCheck() {
  const [url, setUrl] = useState('')
  const { state, run } = useAnalysis(api.analyzeUrl)

  function submit(event: FormEvent) {
    event.preventDefault()
    const value = url.trim()
    if (value) void run(value)
  }

  return (
    <CheckPage
      title="Check a link"
      intro="Paste a link you received. QRGUARD examines it without opening the page for you."
      state={state}
    >
      <form onSubmit={submit} className="space-y-3">
        <label htmlFor="url" className="block font-medium">
          Link
        </label>
        <input
          id="url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          maxLength={2048}
          placeholder="https://example.com/offer"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          className={inputClass}
        />
        <button type="submit" className={buttonClass} disabled={!url.trim() || state.status === 'loading'}>
          Check link
        </button>
      </form>
    </CheckPage>
  )
}
