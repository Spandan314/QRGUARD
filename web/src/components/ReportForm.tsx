import { useState, type FormEvent } from 'react'
import { useOptionalAuth } from '../context/AuthContext'
import { api, ApiError } from '../services/api'
import type { ReportKind } from '../types/api'

const KINDS: { value: ReportKind; label: string }[] = [
  { value: 'false_positive', label: 'It is genuine (wrongly flagged)' },
  { value: 'false_negative', label: 'It is a scam (missed)' },
  { value: 'scam', label: 'Report as a scam' },
]

/** Lets a signed-in user tell the team a result is wrong. Only the verdict is linked, not content. */
export function ReportForm({ scanId }: { scanId?: string | undefined }) {
  const auth = useOptionalAuth()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<ReportKind>('false_positive')
  const [note, setNote] = useState('')
  const [state, setState] = useState<'idle' | 'sending' | 'sent' | string>('idle')

  if (!auth?.user || !auth.profile) return null
  if (state === 'sent') {
    return (
      <p role="status" className="text-sm text-teal-800 dark:text-teal-300">
        Thank you – your report was sent to the QRGUARD team.
      </p>
    )
  }
  if (!open) {
    return (
      <button type="button" className="text-sm text-teal-700 underline dark:text-teal-400" onClick={() => setOpen(true)}>
        Is this result wrong? Report it
      </button>
    )
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setState('sending')
    try {
      await api.report(kind, note.trim(), scanId)
      setState('sent')
    } catch (error) {
      setState(error instanceof ApiError ? error.message : 'The report could not be sent.')
    }
  }

  return (
    <form onSubmit={submit} className="space-y-2 rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-700" aria-label="Report this result">
      <fieldset className="space-y-1">
        <legend className="font-medium">What is wrong?</legend>
        {KINDS.map((option) => (
          <label key={option.value} className="flex items-center gap-2">
            <input type="radio" name="report-kind" checked={kind === option.value} onChange={() => setKind(option.value)} />
            {option.label}
          </label>
        ))}
      </fieldset>
      <label className="block">
        <span className="font-medium">Note (optional, max 280 characters)</span>
        <textarea
          className="mt-1 w-full rounded border border-slate-300 p-2 dark:border-slate-600 dark:bg-slate-950"
          maxLength={280}
          rows={2}
          value={note}
          onChange={(event) => setNote(event.target.value)}
        />
        <span className="text-xs text-slate-500">Do not include personal data such as account numbers or OTPs.</span>
      </label>
      <div className="flex gap-2">
        <button type="submit" disabled={state === 'sending'} className="rounded bg-teal-700 px-3 py-2 font-semibold text-white disabled:opacity-50">
          Send report
        </button>
        <button type="button" className="px-3 py-2" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
      {state !== 'idle' && state !== 'sending' ? (
        <p role="alert" className="text-red-700 dark:text-red-300">
          {state}
        </p>
      ) : null}
    </form>
  )
}
