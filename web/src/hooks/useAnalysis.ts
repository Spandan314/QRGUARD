import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiError } from '../services/api'
import type { AnalysisResult } from '../types/api'

type State =
  | { status: 'idle' }
  | { status: 'loading' }
  | { status: 'success'; result: AnalysisResult }
  | { status: 'error'; error: ApiError }

/** Runs one analysis at a time; a new run (or leaving the page) cancels the previous request. */
export function useAnalysis<A extends unknown[]>(
  call: (...args: [...A, AbortSignal]) => Promise<AnalysisResult>,
) {
  const [state, setState] = useState<State>({ status: 'idle' })
  const controllerRef = useRef<AbortController | null>(null)

  useEffect(() => () => controllerRef.current?.abort(), [])

  const run = useCallback(
    async (...args: A) => {
      controllerRef.current?.abort()
      const controller = new AbortController()
      controllerRef.current = controller
      setState({ status: 'loading' })
      try {
        const result = await call(...args, controller.signal)
        if (!controller.signal.aborted) setState({ status: 'success', result })
      } catch (error) {
        if (controller.signal.aborted) return
        const apiError =
          error instanceof ApiError
            ? error
            : new ApiError(0, 'UNKNOWN', 'Something went wrong. Please try again.')
        setState({ status: 'error', error: apiError })
      }
    },
    [call],
  )

  const reset = useCallback(() => {
    controllerRef.current?.abort()
    setState({ status: 'idle' })
  }, [])

  return { state, run, reset }
}
