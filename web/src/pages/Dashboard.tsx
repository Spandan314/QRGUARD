import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { api } from '../services/api'
import type { HealthResponse } from '../types/api'

const CHECKS = [
  { to: '/check/url', icon: '🔗', title: 'Check a link', text: 'Look-alike domains, hidden redirects, known phishing sites.' },
  { to: '/check/message', icon: '💬', title: 'Check a message', text: 'Fake KYC, OTP requests, job and prize scams, UPI tricks.' },
  { to: '/check/screenshot', icon: '📱', title: 'Check a screenshot', text: 'Reads the text and QR codes in a screenshot and checks them.' },
  { to: '/check/qr', icon: '🔳', title: 'Check a QR code', text: 'Links, UPI payment requests, Wi-Fi and more.' },
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

  if (status.state === 'checking') return <p className="text-sm text-slate-500">Connecting to the QRGUARD server…</p>
  if (status.state === 'down') {
    return (
      <p className="text-sm text-amber-800 dark:text-amber-300">
        ⚠️ The QRGUARD server is not reachable right now (it may be starting up). Checks will fail until it is back.
      </p>
    )
  }
  const ti = status.health.components.threat_intel
  const sources = ti?.providers.filter((p) => p.enabled).length ?? 0
  return (
    <p className="text-sm text-slate-600 dark:text-slate-300" data-testid="backend-status">
      ✅ Server online · engine {status.health.engine_version}
      {status.health.components.ocr_engine ? ` · text recognition ${status.health.components.ocr_engine.replace('_', ' ')}` : ''}
      {ti ? ` · ${sources} threat-intelligence source${sources === 1 ? '' : 's'} active` : ''}
    </p>
  )
}

export default function Dashboard() {
  return (
    <div className="space-y-8">
      <section className="space-y-3">
        <h1 className="text-3xl font-bold sm:text-4xl">Is it a scam? Check before you click, pay or scan.</h1>
        <p className="max-w-3xl text-lg text-slate-600 dark:text-slate-300">
          QRGUARD explains the warning signs in links, messages, screenshots and QR codes, and tells you what to do. It
          never opens the links you check.
        </p>
        <BackendStatus />
      </section>
      <section aria-label="Checks" className="grid gap-4 sm:grid-cols-2">
        {CHECKS.map((check) => (
          <Link
            key={check.to}
            to={check.to}
            className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-teal-600 dark:border-slate-700 dark:bg-slate-900"
          >
            <span className="text-3xl" aria-hidden="true">
              {check.icon}
            </span>
            <h2 className="mt-2 text-xl font-semibold">{check.title}</h2>
            <p className="mt-1 text-slate-600 dark:text-slate-300">{check.text}</p>
          </Link>
        ))}
      </section>
      <section className="rounded-2xl bg-teal-700 p-5 text-white">
        <h2 className="text-lg font-semibold">How to read a result</h2>
        <ul className="mt-2 space-y-1">
          <li>✅ SAFE (0–29): no significant warning signs – not a guarantee.</li>
          <li>⚠️ SUSPICIOUS (30–59): several warning signs – do not trust it.</li>
          <li>⛔ MALICIOUS (60–100): strong evidence of a scam or attack.</li>
          <li>🔎 VERIFIED means a trusted list confirms it (legitimate site or known threat).</li>
        </ul>
      </section>
    </div>
  )
}
