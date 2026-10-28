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
  if (status.state === 'checking') return <p className="text-sm text-muted">Connecting to the QRGUARD server…</p>
  if (status.state === 'down') {
    return (
      <p className="inline-flex items-center gap-2 text-sm text-warn">
        <Icon name="alert-triangle" className="h-4 w-4" />
        The QRGUARD server is not reachable right now (it may be starting up). Checks will fail until it is back.
      </p>
    )
  }
  const ti = status.health.components.threat_intel
  const sources = ti?.providers.filter((p) => p.enabled).length ?? 0
  return (
    <p className="inline-flex flex-wrap items-center gap-2 font-mono text-xs text-muted" data-testid="backend-status">
      <span className="h-2 w-2 rounded-full bg-accent" aria-hidden="true" />
      Server online · engine {status.health.engine_version}
      {status.health.components.ocr_engine ? ` · text recognition ${status.health.components.ocr_engine.replace('_', ' ')}` : ''}
      {ti ? ` · ${sources} threat-intelligence source${sources === 1 ? '' : 's'} active` : ''}
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
        { at: 0, text: `specimen sealed: ${SPECIMEN_LABEL[shown.kind]}`, tone: 'normal' },
        { at: 0, text: 'sent to our server · your device does not open it', tone: 'normal' },
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
      window.setTimeout(() => setLog((current) => [...current, { at: answeredAt, text: 'server answered', tone: 'normal' }]), 0),
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
    const id = window.setTimeout(() => setLog((current) => [...current, { at, text: `aborted: ${state.error.message}`, tone: 'danger' }]), 0)
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
        <h1 className="text-4xl font-bold tracking-tight sm:text-6xl">Put it in the airlock.</h1>
        <p className="text-lg text-muted">
          Links go in sealed. We decode, follow and inspect them on our side. Only the verdict comes out to you.
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
            <h2 className="label-mono font-mono">Camera · nothing is recorded</h2>
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

      <div className="grid gap-5 md:grid-cols-2">
        <ChamberLog lines={log} running={state.status === 'loading'} />
        <section aria-label="What the airlock guarantees" className="flex flex-col justify-between gap-5 rounded-panel border border-line bg-panel p-5 sm:p-6">
          <div>
            <h2 className="label-mono font-mono">What the airlock guarantees</h2>
            <p className="mt-3 font-display text-xl leading-snug font-semibold sm:text-2xl">
              Your device never touches the link. The release door only opens if you choose to, after you’ve read the verdict.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button type="button" className={primaryButton} onClick={newSpecimen}>
              Load a new specimen
            </button>
            <button type="button" className={secondaryButton} onClick={() => setCamera(true)} disabled={busy}>
              Scan with camera
            </button>
          </div>
        </section>
      </div>

      {state.status === 'error' ? <ErrorAlert error={state.error} /> : null}
      {result && phase === 'done' ? <ResultCard result={result} /> : null}
    </div>
  )
}
