import type { ReactNode } from 'react'
import type { ApiError } from '../services/api'
import type { AnalysisResult } from '../types/api'
import { ErrorAlert } from './ErrorAlert'
import { ResultCard } from './ResultCard'

type State =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; result: AnalysisResult }
  | { status: 'error'; error: ApiError }

/** Shared page frame: title, input form, then loading / error / result. */
export function CheckPage({
  title,
  intro,
  state,
  children,
}: {
  title: string
  intro: ReactNode
  state: State
  children: ReactNode
}) {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">{title}</h1>
        <div className="mt-2 text-slate-600 dark:text-slate-300">{intro}</div>
      </div>
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900">
        {children}
      </div>
      {state.status === 'loading' ? (
        <p role="status" className="animate-pulse text-center text-slate-600 dark:text-slate-300">
          Checking… this can take a few seconds.
        </p>
      ) : null}
      {state.status === 'error' ? <ErrorAlert error={state.error} /> : null}
      {state.status === 'success' ? <ResultCard result={state.result} /> : null}
    </div>
  )
}

export const buttonClass =
  'inline-flex min-h-11 items-center justify-center rounded-lg bg-teal-700 px-5 py-2.5 font-semibold text-white hover:bg-teal-800 disabled:cursor-not-allowed disabled:opacity-50'

export const inputClass =
  'w-full rounded-lg border border-slate-300 bg-white px-3 py-2.5 text-base dark:border-slate-600 dark:bg-slate-950'
