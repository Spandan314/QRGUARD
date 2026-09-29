import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ErrorAlert } from '../components/ErrorAlert'
import { RiskBadge } from '../components/RiskBadge'
import { useAuth } from '../context/AuthContext'
import { api, ApiError } from '../services/api'
import type { HistoryItem } from '../types/api'

const TYPE_LABEL: Record<HistoryItem['input_type'], string> = {
  url: 'Link',
  message: 'Message',
  screenshot: 'Screenshot',
  qr_camera: 'QR (camera)',
  qr_image: 'QR (image)',
}

function describeTarget(item: HistoryItem): string {
  const t = item.target
  if (t.kind === 'url') return t.domain ?? 'link'
  if (t.kind === 'upi') return `UPI payment${t.payee_domain ? ` (${t.payee_domain})` : ''}`
  if (t.kind === 'message' || t.kind === 'screenshot') {
    return `${t.length ?? '?'} characters, ${t.url_count ?? 0} link${t.url_count === 1 ? '' : 's'}`
  }
  return `QR code (${t.kind})`
}

function HistoryRow({ item, onDelete }: { item: HistoryItem; onDelete: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  return (
    <li className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900" data-testid="history-item">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <RiskBadge level={item.risk_level} size="sm" />
          <span className="font-mono text-sm">{item.risk_score}/100</span>
          <span className="text-sm text-slate-600 dark:text-slate-300">
            {TYPE_LABEL[item.input_type]} · {describeTarget(item)}
          </span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <time dateTime={item.created_at} className="text-slate-500">
            {new Date(item.created_at).toLocaleString()}
          </time>
          <button type="button" className="text-teal-700 underline dark:text-teal-400" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? 'Hide' : 'Details'}
          </button>
          <button type="button" className="text-red-700 underline dark:text-red-300" onClick={() => onDelete(item.id)} aria-label="Delete this result">
            Delete
          </button>
        </div>
      </div>
      {open ? (
        <div className="mt-3 space-y-2 text-sm">
          <p>
            {item.verification.status === 'VERIFIED' ? '🔎 Verified' : '❔ Unverified'} · confidence {item.confidence.toLowerCase()}
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {item.indicators.map((indicator, index) => (
              <li key={`${indicator.id}-${index}`}>
                {indicator.title ?? indicator.id}
                {indicator.score_contribution ? ` (+${Math.round(indicator.score_contribution * 10) / 10})` : ''}
              </li>
            ))}
          </ul>
          {item.recommended_action ? <p className="text-slate-700 dark:text-slate-300">{item.recommended_action}</p> : null}
        </div>
      ) : null}
    </li>
  )
}

export default function History() {
  const { user, ready } = useAuth()
  const [items, setItems] = useState<HistoryItem[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)

  const load = useCallback(async (next: string | null) => {
    try {
      const page = await api.history(next)
      setItems((current) => (next ? [...current, ...page.items] : page.items))
      setCursor(page.next_cursor)
      setLoaded(true)
      setError(null)
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!user) return
    let active = true
    api.history(null).then(
      (page) => {
        if (!active) return
        setItems(page.items)
        setCursor(page.next_cursor)
        setLoaded(true)
      },
      (caught: unknown) => active && caught instanceof ApiError && setError(caught),
    )
    return () => {
      active = false
    }
  }, [user])

  async function remove(id: string) {
    try {
      await api.deleteHistoryItem(id)
      setItems((current) => current.filter((item) => item.id !== id))
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  async function removeAll() {
    try {
      await api.deleteAllHistory()
      setItems([])
      setCursor(null)
      setConfirmAll(false)
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  if (!ready) return <p role="status">Loading…</p>
  if (!user) {
    return (
      <div className="space-y-3">
        <h1 className="text-3xl font-bold">My history</h1>
        <p>
          <Link to="/account" className="text-teal-700 underline dark:text-teal-400">
            Sign in
          </Link>{' '}
          to keep a private history of your checks.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-3xl font-bold">My history</h1>
        {items.length > 0 ? (
          confirmAll ? (
            <span className="flex items-center gap-2" role="alertdialog" aria-label="Confirm delete all">
              Delete all saved results?
              <button type="button" className="rounded bg-red-700 px-3 py-2 font-semibold text-white" onClick={() => void removeAll()}>
                Delete all
              </button>
              <button type="button" className="px-3 py-2" onClick={() => setConfirmAll(false)}>
                Cancel
              </button>
            </span>
          ) : (
            <button type="button" className="rounded border border-red-700 px-3 py-2 text-red-700 dark:text-red-300" onClick={() => setConfirmAll(true)}>
              Delete all
            </button>
          )
        ) : null}
      </div>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Only verdicts are saved – never your messages, screenshots, QR contents or full links. Results are removed
        automatically after 90 days.
      </p>
      {error ? <ErrorAlert error={error} /> : null}
      {loaded && items.length === 0 ? <p>No saved results yet.</p> : null}
      <ul className="space-y-3">
        {items.map((item) => (
          <HistoryRow key={item.id} item={item} onDelete={(id) => void remove(id)} />
        ))}
      </ul>
      {loading || (!loaded && !error) ? <p role="status">Loading…</p> : null}
      {cursor && !loading ? (
        <button
          type="button"
          className="rounded border border-slate-300 px-4 py-2 dark:border-slate-600"
          onClick={() => {
            setLoading(true)
            void load(cursor)
          }}
        >
          Load more
        </button>
      ) : null}
    </div>
  )
}
