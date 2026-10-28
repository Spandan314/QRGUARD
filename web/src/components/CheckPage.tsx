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
        <div className="mt-2 max-w-3xl text-slate-600 dark:text-slate-300">{intro}</div>
      </header>
      <div className={panelClass}>{children}</div>
      {state.status === 'loading' ? <AnalysisProgress kind={kind} decodedOnDevice={decodedOnDevice} /> : null}
      {state.status === 'error' ? <ErrorAlert error={state.error} /> : null}
      {state.status === 'success' ? <ResultCard result={state.result} /> : null}
    </div>
  )
}

export const panelClass =
  'rounded-lg border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900'

export const buttonClass =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-md bg-teal-700 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50'

export const inputClass =
  'w-full rounded-md border border-slate-300 bg-white px-3 py-2.5 text-base shadow-sm placeholder:text-slate-400 focus:border-teal-600 dark:border-slate-600 dark:bg-slate-950'
