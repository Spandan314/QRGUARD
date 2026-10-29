import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router'
import { ErrorAlert } from '../components/ErrorAlert'
import { RiskBadge } from '../components/RiskBadge'
import { formatDateTime } from '../utils/format'
import { verdictLabel } from '../utils/verdict'
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
    <li className="rounded-panel border border-line bg-panel p-4" data-testid="history-item">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-3">
          <RiskBadge verdict={verdictLabel(item.risk_level, item.verification)} size="sm" />
          <span className="font-mono text-sm">{item.risk_score}/100</span>
          <span className="text-sm text-muted">
            {TYPE_LABEL[item.input_type]} · {describeTarget(item)}
          </span>
        </div>
        <div className="flex items-center gap-2 text-sm">
          <time dateTime={item.created_at} className="text-muted">
            {formatDateTime(item.created_at)}
          </time>
          <button type="button" className="inline-flex min-h-11 items-center rounded-btn border border-line px-3 font-medium text-accent hover:bg-panel-2" onClick={() => setOpen(!open)} aria-expanded={open}>
            {open ? 'Hide' : 'Details'}
          </button>
          <button type="button" className="inline-flex min-h-11 items-center rounded-btn border border-danger/40 px-3 font-medium text-danger hover:bg-danger/10" onClick={() => onDelete(item.id)} aria-label="Delete this result">
            Delete
          </button>
        </div>
      </div>
      {open ? (
        <div className="mt-3 space-y-2 text-sm">
          <p>
            {item.verification.status === 'VERIFIED' ? 'Verified' : 'Unverified'} · confidence {item.confidence.toLowerCase()}
          </p>
          <ul className="list-disc space-y-1 pl-5">
            {item.indicators.map((indicator, index) => (
              <li key={`${indicator.id}-${index}`}>
                {indicator.title ?? indicator.id}
                {indicator.score_contribution ? ` (+${Math.round(indicator.score_contribution * 10) / 10})` : ''}
              </li>
            ))}
          </ul>
          {item.recommended_action ? <p className="text-ink">{item.recommended_action}</p> : null}
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
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">My history</h1>
        <p>
          <Link to="/account" className="text-accent underline">
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
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">My history</h1>
        {items.length > 0 ? (
          confirmAll ? (
            <span className="flex items-center gap-2" role="alertdialog" aria-label="Confirm delete all">
              Delete all saved results?
              <button type="button" className="min-h-11 rounded-btn bg-danger px-3 py-2 font-semibold text-surface" onClick={() => void removeAll()}>
                Delete all
              </button>
              <button type="button" className="px-3 py-2" onClick={() => setConfirmAll(false)}>
                Cancel
              </button>
            </span>
          ) : (
            <button type="button" className="min-h-11 rounded-btn border border-danger px-3 py-2 text-danger" onClick={() => setConfirmAll(true)}>
              Delete all
            </button>
          )
        ) : null}
      </div>
      <p className="text-sm text-muted">
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
          className="min-h-11 rounded-btn border border-line px-4 py-2"
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
