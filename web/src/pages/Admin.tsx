import { useEffect, useState } from 'react'
import { ErrorAlert } from '../components/ErrorAlert'
import { useAuth } from '../context/AuthContext'
import { api, ApiError } from '../services/api'
import type { AdminReport, AdminStats } from '../types/api'
import { PROVIDER_NAME } from '../utils/format'

const REPORT_LABEL: Record<AdminReport['reported_as'], string> = {
  false_positive: 'False positive',
  false_negative: 'False negative',
  scam: 'Scam report',
}

/** Admin dashboard. The page guard is cosmetic: the backend enforces the admin claim. */
export default function Admin() {
  const { profile, ready } = useAuth()
  const [stats, setStats] = useState<AdminStats | null>(null)
  const [reports, setReports] = useState<AdminReport[]>([])
  const [status, setStatus] = useState<'open' | 'reviewed'>('open')
  const [error, setError] = useState<ApiError | null>(null)

  useEffect(() => {
    if (!profile?.admin) return
    let active = true
    Promise.all([api.adminStats(30), api.adminReports(status)]).then(
      ([nextStats, nextReports]) => {
        if (!active) return
        setStats(nextStats)
        setReports(nextReports.items)
      },
      (caught: unknown) => active && caught instanceof ApiError && setError(caught),
    )
    return () => {
      active = false
    }
  }, [profile, status])

  async function mark(id: string, next: 'open' | 'reviewed') {
    try {
      await api.adminUpdateReport(id, next)
      setReports((current) => current.filter((report) => report.id !== id))
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  if (!ready) return <p role="status">Loading…</p>
  if (!profile?.admin) {
    return (
      <div className="space-y-2">
        <h1 className="text-3xl font-bold">Admin</h1>
        <p>Administrator access is required.</p>
      </div>
    )
  }

  const totals = (stats?.days ?? []).reduce(
    (sum, day) => ({
      total: sum.total + day.total,
      SAFE: sum.SAFE + (day.by_level.SAFE ?? 0),
      SUSPICIOUS: sum.SUSPICIOUS + (day.by_level.SUSPICIOUS ?? 0),
      MALICIOUS: sum.MALICIOUS + (day.by_level.MALICIOUS ?? 0),
    }),
    { total: 0, SAFE: 0, SUSPICIOUS: 0, MALICIOUS: 0 },
  )

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Admin dashboard</h1>
      {error ? <ErrorAlert error={error} /> : null}
      {!stats ? <p role="status">Loading statistics…</p> : null}
      <section aria-label="Last 30 days" className={stats ? 'grid gap-3 sm:grid-cols-4' : 'hidden'}>
        {(
          [
            ['Checks', totals.total],
            ['✅ Safe', totals.SAFE],
            ['⚠️ Suspicious', totals.SUSPICIOUS],
            ['⛔ Malicious', totals.MALICIOUS],
          ] as const
        ).map(([label, value]) => (
          <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-700 dark:bg-slate-900">
            <p className="text-sm text-slate-500">{label} (30 days)</p>
            <p className="text-2xl font-bold" data-testid={`stat-${label}`}>
              {value}
            </p>
          </div>
        ))}
      </section>
      {stats ? (
        <section>
          <h2 className="mb-2 text-xl font-semibold">Per day</h2>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr>
                  <th className="p-2">Date</th>
                  <th className="p-2">Checks</th>
                  <th className="p-2">Malicious</th>
                  <th className="p-2">Threat intel unavailable</th>
                </tr>
              </thead>
              <tbody>
                {stats.days.map((day) => (
                  <tr key={day.date} className="border-t border-slate-200 dark:border-slate-700">
                    <td className="p-2">{day.date}</td>
                    <td className="p-2">{day.total}</td>
                    <td className="p-2">{day.by_level.MALICIOUS ?? 0}</td>
                    <td className="p-2">{day.ti_unavailable}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <h2 className="mb-2 mt-6 text-xl font-semibold">Threat-intelligence sources</h2>
          <ul className="text-sm">
            {stats.threat_intel.map((p) => (
              <li key={p.provider}>
                {PROVIDER_NAME[p.provider] ?? p.provider}: {p.enabled ? 'enabled' : 'not enabled'}
                {p.external ? ' (external service)' : ' (local)'}
              </li>
            ))}
          </ul>
        </section>
      ) : null}
      <section className="space-y-2">
        <div className="flex items-center gap-3">
          <h2 className="text-xl font-semibold">User reports</h2>
          <select
            aria-label="Report status"
            value={status}
            onChange={(e) => setStatus(e.target.value as 'open' | 'reviewed')}
            className="rounded border border-slate-300 px-2 py-1 dark:border-slate-600 dark:bg-slate-950"
          >
            <option value="open">Open</option>
            <option value="reviewed">Reviewed</option>
          </select>
        </div>
        {reports.length === 0 ? <p className="text-sm">No {status} reports.</p> : null}
        <ul className="space-y-2">
          {reports.map((report) => (
            <li key={report.id} className="rounded-lg border border-slate-200 p-3 text-sm dark:border-slate-700" data-testid="admin-report">
              <p className="font-medium">
                {REPORT_LABEL[report.reported_as]}
                {report.domain ? ` · ${report.domain}` : ''} · {new Date(report.created_at).toLocaleString()}
              </p>
              {report.note ? <p className="mt-1 whitespace-pre-wrap">{report.note}</p> : null}
              <button
                type="button"
                className="mt-2 text-teal-700 underline dark:text-teal-400"
                onClick={() => void mark(report.id, status === 'open' ? 'reviewed' : 'open')}
              >
                {status === 'open' ? 'Mark as reviewed' : 'Reopen'}
              </button>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
