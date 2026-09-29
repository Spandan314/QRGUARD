import { useState, type FormEvent } from 'react'
import { buttonClass, CheckPage, inputClass } from '../components/CheckPage'
import { useAnalysis } from '../hooks/useAnalysis'
import { api } from '../services/api'

const MAX_CHARS = 5000

export default function MessageCheck() {
  const [text, setText] = useState('')
  const { state, run } = useAnalysis(api.analyzeMessage)

  function submit(event: FormEvent) {
    event.preventDefault()
    if (text.trim()) void run(text)
  }

  return (
    <CheckPage
      title="Check a message"
      intro="Paste an SMS, WhatsApp or e-mail message. Links inside it are checked too. The text is not stored."
      state={state}
    >
      <form onSubmit={submit} className="space-y-3">
        <label htmlFor="message" className="block font-medium">
          Message text
        </label>
        <textarea
          id="message"
          name="message"
          rows={7}
          maxLength={MAX_CHARS}
          placeholder="Dear customer, your account will be blocked today…"
          value={text}
          onChange={(event) => setText(event.target.value)}
          className={inputClass}
        />
        <div className="flex items-center justify-between">
          <button type="submit" className={buttonClass} disabled={!text.trim() || state.status === 'loading'}>
            Check message
          </button>
          <span className="text-sm text-slate-500 dark:text-slate-400">
            {text.length} / {MAX_CHARS}
          </span>
        </div>
      </form>
    </CheckPage>
  )
}
