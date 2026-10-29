import type { ReactNode } from 'react'
import type { ApiError } from '../services/api'
import type { AnalysisResult } from '../types/api'
import { AnalysisProgress, type AnalysisKind } from './AnalysisProgress'
import { ErrorAlert } from './ErrorAlert'
import { ResultCard } from './ResultCard'

type State =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; result: AnalysisResult }
  | { status: 'error'; error: ApiError }

/** Shared page frame: title, input panel, then progress / error / result. */
export function CheckPage({
  title,
  intro,
  state,
  kind,
  decodedOnDevice = false,
  children,
}: {
  title: string
  intro: ReactNode
  state: State
  kind: AnalysisKind
  decodedOnDevice?: boolean
  children: ReactNode
}) {
  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h1>
        <div className="mt-2 max-w-3xl text-muted">{intro}</div>
      </header>
      <div className={panelClass}>{children}</div>
      {state.status === 'loading' ? <AnalysisProgress kind={kind} decodedOnDevice={decodedOnDevice} /> : null}
      {state.status === 'error' ? <ErrorAlert error={state.error} /> : null}
      {state.status === 'success' ? <ResultCard result={state.result} /> : null}
    </div>
  )
}

export const panelClass =
  'rounded-panel border border-line bg-panel p-5'

export const buttonClass =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-btn bg-accent px-5 py-2.5 text-sm font-semibold text-on-accent hover:bg-accent/90 disabled:cursor-not-allowed disabled:opacity-50'

export const inputClass =
  'w-full rounded-btn border border-line bg-panel-2 px-3 py-2.5 text-base placeholder:text-muted focus:border-accent'
