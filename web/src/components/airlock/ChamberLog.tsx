import type { LogLine } from '../../utils/airlock'

export interface TimedLine extends LogLine {
  /** Seconds since the specimen was submitted, measured on this device when the line appeared. */
  at: number
}

const TONE: Record<LogLine['tone'], string> = { normal: 'text-ink', warn: 'text-warn', danger: 'text-danger' }

const stamp = (seconds: number) => seconds.toFixed(2).padStart(5, '0')

export function ChamberLog({ lines, running }: { lines: TimedLine[]; running: boolean }) {
  return (
    <section aria-label="What we did" className="rounded-panel border border-line bg-panel p-5 sm:p-6">
      <h2 className="label-mono font-mono">What we did</h2>
      <ol className="mt-3 space-y-1.5 font-mono text-[13px] leading-relaxed" aria-live="polite" data-testid="chamber-log">
        {lines.length === 0 && !running ? <li className="text-muted">Nothing checked yet.</li> : null}
        {lines.map((line, index) => (
          <li key={index} className="flex gap-3">
            <span className="shrink-0 text-muted tabular-nums">{stamp(line.at)}</span>
            <span className={`min-w-0 break-words ${TONE[line.tone]}`}>{line.text}</span>
          </li>
        ))}
        {running ? (
          <li className="flex gap-3 text-muted">
            <span className="shrink-0">·····</span>
            <span>
              inspecting on our server
              <span className="ml-0.5 inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-accent motion-reduce:animate-none" aria-hidden="true" />
            </span>
          </li>
        ) : null}
      </ol>
      <p className="mt-3 text-xs text-muted">Times are seconds since you pressed “Check it”.</p>
    </section>
  )
}
