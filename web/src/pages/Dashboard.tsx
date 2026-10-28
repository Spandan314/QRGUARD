import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { Icon, type IconName } from '../components/Icon'
import { RiskBadge } from '../components/RiskBadge'
import { api } from '../services/api'
import type { HealthResponse } from '../types/api'

type Check = { to: string; icon: IconName; title: string; text: string }

const PRIMARY: Check[] = [
  { to: '/check/qr', icon: 'qr', title: 'Check a QR code', text: 'Upload a photo or scan with your camera. Links, UPI payments, Wi-Fi and more.' },
  { to: '/check/url', icon: 'link', title: 'Check a link', text: 'Paste a URL. Structure, look-alike domains, shortened links and threat lists.' },
]
const SECONDARY: Check[] = [
  { to: '/check/message', icon: 'message', title: 'Check a message', text: 'Fake KYC, OTP requests, job and prize scams, UPI tricks.' },
  { to: '/check/screenshot', icon: 'screenshot', title: 'Check a screenshot', text: 'Reads the text and QR codes in a screenshot.' },
]

type Status = { state: 'checking' } | { state: 'ok'; health: HealthResponse } | { state: 'down' }

function BackendStatus() {
  const [status, setStatus] = useState<Status>({ state: 'checking' })
  useEffect(() => {
    const controller = new AbortController()
    api
      .health(controller.signal)
      .then((health) => setStatus({ state: 'ok', health }))
      .catch(() => {
        if (!controller.signal.aborted) setStatus({ state: 'down' })
      })
    return () => controller.abort()
  }, [])

  if (status.state === 'checking') {
    return <p className="text-sm text-slate-500 dark:text-slate-400">Connecting to the QRGUARD server…</p>
  }
  if (status.state === 'down') {
    return (
      <p className="inline-flex items-center gap-2 text-sm text-amber-800 dark:text-amber-300">
        <Icon name="alert-triangle" className="h-4 w-4" />
        The QRGUARD server is not reachable right now (it may be starting up). Checks will fail until it is back.
      </p>
    )
  }
  const ti = status.health.components.threat_intel
  const sources = ti?.providers.filter((p) => p.enabled).length ?? 0
  return (
    <p className="inline-flex flex-wrap items-center gap-2 text-sm text-slate-600 dark:text-slate-300" data-testid="backend-status">
      <span className="h-2 w-2 rounded-full bg-emerald-500" aria-hidden="true" />
      Server online · engine {status.health.engine_version}
      {status.health.components.ocr_engine ? ` · text recognition ${status.health.components.ocr_engine.replace('_', ' ')}` : ''}
      {ti ? ` · ${sources} threat-intelligence source${sources === 1 ? '' : 's'} active` : ''}
    </p>
  )
}

function CheckCard({ check, primary = false }: { check: Check; primary?: boolean }) {
  return (
    <Link
      to={check.to}
      className={`group flex gap-4 rounded-lg border bg-white p-5 shadow-sm transition-colors hover:border-teal-600 dark:bg-slate-900 ${
        primary ? 'border-slate-200 dark:border-slate-700' : 'border-slate-200 dark:border-slate-800'
      }`}
    >
      <span
        className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-md ${
          primary ? 'bg-teal-700 text-white' : 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300'
        }`}
      >
        <Icon name={check.icon} />
      </span>
      <span className="min-w-0">
        <span className="flex items-center gap-1.5 font-semibold">
          {check.title}
          <Icon name="arrow-right" className="h-4 w-4 text-slate-400 transition-transform group-hover:translate-x-0.5" />
        </span>
        <span className="mt-1 block text-sm text-slate-600 dark:text-slate-300">{check.text}</span>
      </span>
    </Link>
  )
}

const LEGEND = [
  { verdict: 'SAFE' as const, text: 'Recognised legitimate website and no significant warning signs. Not a guarantee.' },
  { verdict: 'UNVERIFIED' as const, text: 'Not enough evidence either way. Not being on a threat list is not proof of safety.' },
  { verdict: 'SUSPICIOUS' as const, text: 'Score 30–59: several warning signs. Do not trust it.' },
  { verdict: 'MALICIOUS' as const, text: 'Score 60–100: strong evidence of a scam or attack, or listed by a threat source.' },
]

export default function Dashboard() {
  return (
    <div className="space-y-8">
      <section className="space-y-3">
        <p className="text-xs font-semibold uppercase tracking-wider text-teal-700 dark:text-teal-400">QR and link security analysis</p>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">Check a QR code or link before you click, pay or scan.</h1>
        <p className="max-w-3xl text-slate-600 dark:text-slate-300">
          QRGUARD analyses the link itself, checks threat-intelligence sources, explains every warning sign and tells you
          what to do. It never opens the links you check.
        </p>
        <BackendStatus />
      </section>
      <section aria-label="Checks" className="space-y-3">
        <div className="grid gap-3 md:grid-cols-2">
          {PRIMARY.map((check) => (
            <CheckCard key={check.to} check={check} primary />
          ))}
        </div>
        <div className="grid gap-3 md:grid-cols-2">
          {SECONDARY.map((check) => (
            <CheckCard key={check.to} check={check} />
          ))}
        </div>
      </section>
      <section className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900">
        <h2 className="text-sm font-semibold">How to read a result</h2>
        <dl className="mt-3 divide-y divide-slate-100 text-sm dark:divide-slate-800">
          {LEGEND.map((row) => (
            <div key={row.verdict} className="grid gap-1 py-2.5 sm:grid-cols-[9rem_1fr] sm:items-center">
              <dt>
                <RiskBadge verdict={row.verdict} size="sm" />
              </dt>
              <dd className="text-slate-600 dark:text-slate-300">{row.text}</dd>
            </div>
          ))}
        </dl>
      </section>
    </div>
  )
}
