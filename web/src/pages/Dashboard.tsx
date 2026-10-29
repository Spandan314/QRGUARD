import { useCallback, useEffect, useRef, useState } from 'react'
import { Chamber, type ChamberPhase } from '../components/airlock/Chamber'
import { ChamberLog, type TimedLine } from '../components/airlock/ChamberLog'
import { primaryButton, secondaryButton, UniversalInput } from '../components/airlock/UniversalInput'
import { ErrorAlert } from '../components/ErrorAlert'
import { Icon } from '../components/Icon'
import { QrCameraScanner } from '../components/QrCameraScanner'
import { ResultCard } from '../components/ResultCard'
import { SaveToHistory, useSaveOption } from '../components/SaveToHistory'
import { useAnalysis } from '../hooks/useAnalysis'
import { api, type AnalyzeOptions } from '../services/api'
import type { AnalysisResult, HealthResponse } from '../types/api'
import {
  chamberLog,
  detectInput,
  finalDestination,
  finishedStages,
  idleStages,
  runningStages,
  SPECIMEN_LABEL,
  upiPayload,
  type Specimen,
  type Stage,
} from '../utils/airlock'
import { verdictOf } from '../utils/verdict'

type Load =
  | { kind: 'link' | 'upi' | 'message'; text: string }
  | { kind: 'image'; file: File }
  | { kind: 'camera'; content: string }

/** Sends each kind of specimen to the existing analysis endpoint for it. */
function analyzeSpecimen(load: Load, options: AnalyzeOptions, signal: AbortSignal): Promise<AnalysisResult> {
  switch (load.kind) {
    case 'link':
      return api.analyzeUrl(load.text, options, signal)
    case 'upi':
      return api.analyzeQrContent(upiPayload(load.text), options, signal)
    case 'message':
      return api.analyzeMessage(load.text, options, signal)
    case 'image':
      return api.analyzeScreenshot(load.file, options, signal) // QR codes AND text in the image
    case 'camera':
      return api.analyzeQrContent(load.content, options, signal)
  }
}

const REVEAL_STEP_MS = 280
const prefersReducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false

type Status = { state: 'checking' } | { state: 'waking' } | { state: 'ok'; health: HealthResponse } | { state: 'down' }

// A free-plan server sleeps when idle and needs up to about a minute to wake, so one failed
// health check is not "down": keep trying for WAKE_LIMIT_MS before saying it cannot be reached.
const WAKE_LIMIT_MS = 90_000
const RETRY_EVERY_MS = 5_000

function BackendStatus() {
  const [status, setStatus] = useState<Status>({ state: 'checking' })
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    const started = Date.now()
    let timer: number | undefined
    const ping = () => {
      api
        .health(controller.signal)
        .then((health) => setStatus({ state: 'ok', health }))
        .catch(() => {
          if (controller.signal.aborted) return
          if (Date.now() - started < WAKE_LIMIT_MS) {
            setStatus({ state: 'waking' })
            timer = window.setTimeout(ping, RETRY_EVERY_MS)
          } else {
            setStatus({ state: 'down' })
          }
        })
    }
    ping()
    return () => {
      controller.abort()
      window.clearTimeout(timer)
    }
  }, [attempt])
  if (status.state === 'checking') return <p className="text-sm text-muted">Getting ready…</p>
  if (status.state === 'waking') {
    return (
      <p className="text-sm text-muted" role="status" data-testid="backend-status" data-state="waking">
        Starting the checker. The first check of the day can take up to a minute; please wait.
      </p>
    )
  }
  if (status.state === 'down') {
    return (
      <div className="flex flex-wrap items-center gap-3 text-sm text-warn" role="alert" data-testid="backend-status" data-state="down">
        <span className="inline-flex items-center gap-2">
          <Icon name="alert-triangle" className="h-4 w-4" />
          We can’t reach the checker right now, so checks won’t work yet.
        </span>
        <button
          type="button"
          className="min-h-11 rounded-btn border border-line px-3 font-medium text-ink hover:bg-panel"
          onClick={() => {
            setStatus({ state: 'checking' })
            setAttempt((n) => n + 1)
          }}
        >
          Try again
        </button>
      </div>
    )
  }
  const ti = status.health.components.threat_intel
  const sources = ti?.providers.filter((p) => p.enabled).length ?? 0
  return (
    <p className="inline-flex flex-wrap items-center gap-2 text-sm text-muted" data-testid="backend-status" data-state="ok">
      <span className="h-2 w-2 rounded-full bg-accent" aria-hidden="true" />
      Ready to check
      {ti && sources ? ` · ${sources} scam database${sources === 1 ? '' : 's'} connected` : ''}
    </p>
  )
}

export default function Dashboard() {
  const { state, run, reset } = useAnalysis(analyzeSpecimen)
  const saveOption = useSaveOption()
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const [specimen, setSpecimen] = useState<Specimen | null>(null)
  const [camera, setCamera] = useState(false)
  const [log, setLog] = useState<TimedLine[]>([])
  const [revealed, setRevealed] = useState(0) // finished stages shown so far (0–5)
  const startedAt = useRef(0)
  const timers = useRef<number[]>([])

  const elapsed = () => (performance.now() - startedAt.current) / 1000
  const clearTimers = () => {
    timers.current.forEach((t) => window.clearTimeout(t))
    timers.current = []
  }
  useEffect(() => clearTimers, [])

  const start = useCallback(
    (load: Load, shown: Specimen) => {
      clearTimers()
      startedAt.current = performance.now()
      setSpecimen(shown)
      setRevealed(0)
      setLog([
        { at: 0, text: `received your ${SPECIMEN_LABEL[shown.kind]}`, tone: 'normal' },
        { at: 0, text: 'sent to our server · your phone does not open it', tone: 'normal' },
      ])
      void run(load, { save: saveOption.save })
    },
    [run, saveOption.save],
  )

  // When the real response arrives, reveal its stages and log lines one after another.
  const result = state.status === 'success' ? state.result : null
  useEffect(() => {
    if (!result) return
    const verdict = verdictOf(result).label
    const lines = chamberLog(result, verdict)
    const answeredAt = elapsed()
    const step = prefersReducedMotion() ? 0 : REVEAL_STEP_MS
    timers.current.push(
      window.setTimeout(() => setLog((current) => [...current, { at: answeredAt, text: 'our server answered', tone: 'normal' }]), 0),
    )
    for (let i = 1; i <= 5; i++) timers.current.push(window.setTimeout(() => setRevealed(i), i * step))
    lines.forEach((line, i) => {
      timers.current.push(
        window.setTimeout(() => setLog((current) => [...current, { ...line, at: elapsed() }]), ((i + 1) * step * 5) / (lines.length + 1)),
      )
    })
    return clearTimers
  }, [result])

  useEffect(() => {
    if (state.status !== 'error') return
    const at = elapsed()
    const id = window.setTimeout(() => setLog((current) => [...current, { at, text: `stopped: ${state.error.message}`, tone: 'danger' }]), 0)
    return () => window.clearTimeout(id)
  }, [state])

  const verdictLabel = result ? verdictOf(result).label : null
  let stages: Stage[] = idleStages()
  let phase: ChamberPhase = 'idle'
  if (state.status === 'loading') {
    stages = runningStages()
    phase = 'running'
  } else if (state.status === 'error') {
    phase = 'failed'
  } else if (result && verdictLabel) {
    const finished = finishedStages(result, verdictLabel)
    stages = runningStages().map((stage, i) => (i < revealed ? (finished[i] as Stage) : stage))
    phase = revealed >= 5 ? 'done' : 'revealing'
  }

  function newSpecimen() {
    clearTimers()
    reset()
    setSpecimen(null)
    setLog([])
    setRevealed(0)
    setCamera(false)
    inputRef.current?.focus()
  }

  const busy = state.status === 'loading' || phase === 'revealing'

  return (
    <div className="space-y-8">
      <section className="max-w-3xl space-y-3">
        <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">Is it a scam? Check before you tap.</h1>
        <p className="text-lg text-muted">
          Paste a link, a UPI ID or a message, or scan a QR code. We check it on our server, so your phone never opens
          it. You get a clear answer and what to do next.
        </p>
        <BackendStatus />
      </section>

      <UniversalInput
        busy={busy}
        inputRef={inputRef}
        onText={(text) => {
          const kind = detectInput(text) ?? 'message'
          start({ kind, text }, { kind, text })
        }}
        onImage={(file) => start({ kind: 'image', file }, { kind: 'image', text: file.name })}
        onCamera={() => setCamera(true)}
      />
      <SaveToHistory option={saveOption} />

      {camera ? (
        <section aria-label="Camera scanner" className="space-y-3 rounded-panel border border-line bg-panel p-5">
          <div className="flex items-center justify-between gap-3">
            <h2 className="label-mono font-mono">Camera · nothing is recorded or saved</h2>
            <button type="button" className={secondaryButton} onClick={() => setCamera(false)}>
              Close camera
            </button>
          </div>
          <QrCameraScanner
            paused={busy}
            onCode={(content) => {
              setCamera(false)
              start({ kind: 'camera', content }, { kind: 'camera', text: content })
            }}
          />
        </section>
      ) : null}

      <Chamber phase={phase} specimen={specimen} destination={result && revealed >= 2 ? finalDestination(result) : null} stages={stages} />

      {state.status === 'error' ? <ErrorAlert error={state.error} /> : null}
      {result && phase === 'done' ? <ResultCard result={result} /> : null}

      <div className="grid gap-5 md:grid-cols-2">
        <ChamberLog lines={log} running={state.status === 'loading'} />
        <section aria-label="How QRGUARD keeps you safe" className="flex flex-col justify-between gap-5 rounded-panel border border-line bg-panel p-5 sm:p-6">
          <div>
            <h2 className="label-mono font-mono">How we keep you safe</h2>
            <p className="mt-3 font-display text-xl leading-snug font-semibold sm:text-2xl">
              Your phone never opens what you check. You see our answer first, and you decide what to do.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={primaryButton} onClick={newSpecimen}>
              Check something else
            </button>
            <button type="button" className={secondaryButton} onClick={() => setCamera(true)} disabled={busy}>
              Scan a QR code
            </button>
          </div>
        </section>
      </div>
    </div>
  )
}
