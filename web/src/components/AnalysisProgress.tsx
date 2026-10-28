import { useEffect, useState } from 'react'
import { Icon } from './Icon'

/** The checks each kind of request really runs on the server (no invented steps). */
export type AnalysisKind = 'url' | 'qr-image' | 'qr-content' | 'message' | 'screenshot'

const URL_CHECKS = [
  'Validating and normalizing the URL',
  'Analyzing URL structure',
  'Checking threat-intelligence sources',
  'Evaluating risk indicators and calculating the score',
]

const ANALYSIS_STAGES: Record<AnalysisKind, string[]> = {
  url: URL_CHECKS,
  'qr-image': ['Decoding the QR code', ...URL_CHECKS],
  'qr-content': URL_CHECKS, // the camera already decoded the code on this device
  message: ['Analyzing the message text', 'Checking the links it contains', 'Calculating the score'],
  screenshot: [
    'Reading the text in the image (OCR)',
    'Decoding any QR codes in the image',
    'Analyzing the text and links',
    'Calculating the score',
  ],
}

/** Server wake-up on the free hosting tier can take this long; only then say so. */
const SLOW_AFTER_SECONDS = 12

/**
 * Shown while the real request is running. The server does not report progress, so the stages
 * are listed as running together, with an indeterminate bar and the real elapsed time – never
 * a made-up percentage or step-by-step ticks. The result replaces this when the response arrives.
 */
export function AnalysisProgress({ kind, decodedOnDevice = false }: { kind: AnalysisKind; decodedOnDevice?: boolean }) {
  const [seconds, setSeconds] = useState(0)
  useEffect(() => {
    const started = Date.now()
    const timer = setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <section
      role="status"
      aria-live="polite"
      aria-label="Analysis in progress"
      className="rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900"
      data-testid="analysis-progress"
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="font-semibold">Analyzing…</h2>
        <span className="text-xs tabular-nums text-slate-500 dark:text-slate-400" data-testid="analysis-elapsed">
          {seconds}s
        </span>
      </div>
      <div className="mt-3 h-1 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800" aria-hidden="true">
        <div className="qg-indeterminate h-full w-2/5 rounded-full bg-teal-600" />
      </div>
      <ol className="mt-4 space-y-2 text-sm">
        {decodedOnDevice ? (
          <li className="flex items-center gap-2.5 text-slate-700 dark:text-slate-300">
            <Icon name="check" className="h-4 w-4 text-teal-700 dark:text-teal-400" />
            QR code decoded on this device
          </li>
        ) : null}
        {ANALYSIS_STAGES[kind].map((stage) => (
          <li key={stage} className="flex items-center gap-2.5 text-slate-700 dark:text-slate-300" data-testid="analysis-stage">
            <span className="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-slate-300 border-t-teal-600 motion-reduce:animate-none dark:border-slate-600 dark:border-t-teal-400" aria-hidden="true" />
            {stage}
          </li>
        ))}
      </ol>
      <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
        {seconds >= SLOW_AFTER_SECONDS
          ? 'Still working – the server may be starting up, which can take up to a minute. You do not need to resubmit.'
          : 'The result appears as soon as the analysis finishes.'}
      </p>
    </section>
  )
}
