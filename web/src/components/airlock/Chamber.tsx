import type { Specimen, Stage, StageState } from '../../utils/airlock'
import { SPECIMEN_LABEL } from '../../utils/airlock'
import { Icon } from '../Icon'

export type ChamberPhase = 'idle' | 'running' | 'revealing' | 'done' | 'failed'

const STAGE_CIRCLE: Record<StageState, string> = {
  done: 'border-accent bg-accent text-on-accent',
  warning: 'border-warn bg-warn text-surface',
  active: 'border-accent bg-panel text-accent',
  waiting: 'border-line bg-panel text-muted',
}

function StageMarker({ state }: { state: StageState }) {
  return (
    <span
      className={`relative z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 ${STAGE_CIRCLE[state]}`}
      aria-hidden="true"
    >
      {state === 'done' ? <Icon name="check" className="h-4 w-4" /> : null}
      {state === 'warning' ? <span className="font-mono text-sm font-bold">!</span> : null}
      {state === 'active' ? (
        <span className="h-4 w-4 animate-spin rounded-full border-2 border-current border-r-transparent motion-reduce:animate-none" />
      ) : null}
    </span>
  )
}

const STATE_TEXT: Record<StageState, string> = { done: 'done', warning: 'warning', active: 'in progress', waiting: 'waiting' }

/** The five-stage track: Decoded → Unshortened → Inspected → Threat lists → Verdict. */
export function StageTrack({ stages }: { stages: Stage[] }) {
  return (
    <ol className="grid grid-cols-1 gap-3 sm:grid-cols-5 sm:gap-0" aria-label="Checking steps">
      {stages.map((stage, index) => {
        const lineDone = index > 0 && stages[index - 1]?.state !== 'waiting' && stages[index - 1]?.state !== 'active'
        return (
          <li
            key={stage.id}
            className="relative flex items-center gap-3 sm:flex-col sm:gap-2 sm:text-center"
            data-testid="stage"
            data-stage={stage.id}
            data-state={stage.state}
          >
            {index > 0 ? (
              <span
                className={`absolute top-5 right-1/2 hidden h-0.5 w-full sm:block ${lineDone ? 'bg-accent' : 'bg-line'}`}
                aria-hidden="true"
              />
            ) : null}
            <StageMarker state={stage.state} />
            <span className="min-w-0">
              <span className="block text-sm font-semibold">{stage.label}</span>
              <span className={`block text-xs ${stage.state === 'warning' ? 'text-warn' : 'text-muted'}`}>
                <span className="sr-only">{STATE_TEXT[stage.state]}: </span>
                {stage.detail}
              </span>
            </span>
          </li>
        )
      })}
    </ol>
  )
}

function Strip({ side, text, tone }: { side: 'left' | 'right'; text: string; tone: 'accent' | 'danger' }) {
  const colour = tone === 'accent' ? 'border-accent text-accent' : 'border-danger text-danger'
  return (
    <div
      className={`flex items-center justify-center bg-panel-2 px-2 py-2 sm:w-14 sm:py-0 ${
        side === 'left' ? 'border-b-2 sm:border-r-2 sm:border-b-0' : 'border-t-2 sm:border-t-0 sm:border-l-2'
      } ${colour}`}
    >
      <span className={`font-mono text-[11px] font-medium tracking-[0.3em] uppercase sm:[writing-mode:vertical-rl] ${side === 'left' ? 'sm:rotate-180' : ''}`}>
        {text}
      </span>
    </div>
  )
}

/**
 * The chamber: the intake is open on the left, the release stays locked on the right until the
 * verdict is out. The link itself never goes past the chamber: it is inspected on our server.
 */
export function Chamber({
  phase,
  specimen,
  destination,
  stages,
}: {
  phase: ChamberPhase
  specimen: Specimen | null
  destination: string | null
  stages: Stage[]
}) {
  const sealed = phase === 'running' || phase === 'revealing'
  const status = phase === 'idle' ? 'Ready' : phase === 'done' ? 'Done' : phase === 'failed' ? 'Stopped' : 'Checking…'
  return (
    <section
      aria-label="Check progress"
      className="flex flex-col overflow-hidden rounded-panel-lg border border-line bg-panel sm:flex-row"
      data-testid="chamber"
      data-phase={phase}
    >
      <Strip side="left" text="Checked here" tone="accent" />
      <div className="min-w-0 flex-1 space-y-6 p-5 sm:p-8">
        <p className="label-mono" data-testid="chamber-status">
          Status · {status}
        </p>
        <div className="rounded-panel border border-dashed border-line bg-panel-2 px-5 py-4" data-testid="specimen">
          <p className="label-mono">
            What you’re checking{specimen ? ` · ${SPECIMEN_LABEL[specimen.kind]}` : ''}
          </p>
          {specimen ? (
            <>
              <p className="mt-2 font-mono text-lg break-all text-ink sm:text-xl">
                {specimen.text.length > 160 ? `${specimen.text.slice(0, 160)}…` : specimen.text}
              </p>
              {destination ? (
                <p className="mt-1 font-mono text-sm break-all text-warn" data-testid="final-destination">
                  <span aria-hidden="true">→ </span>
                  <span className="sr-only">Really leads to: </span>
                  {destination}
                </p>
              ) : null}
            </>
          ) : (
            <p className="mt-2 font-mono text-muted">Nothing yet. Paste something above or scan a QR code.</p>
          )}
        </div>
        <StageTrack stages={stages} />
        {sealed ? <p className="sr-only">Checking on our server. Your phone does not open it.</p> : null}
      </div>
      <Strip side="right" text={phase === 'done' ? 'Answer only' : 'Not opened'} tone={phase === 'done' ? 'accent' : 'danger'} />
    </section>
  )
}
