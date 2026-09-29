import { useRouter } from 'expo-router'
import { useCallback, useEffect, useRef, useState } from 'react'
import { useResult } from '../context/ResultContext'
import { ApiError } from '../services/api'
import type { AnalysisResult } from '../types/api'

/** Runs one analysis at a time and opens the result screen when it succeeds. */
export function useAnalysis<A extends unknown[]>(call: (...args: [...A, AbortSignal]) => Promise<AnalysisResult>) {
  const router = useRouter()
  const { setResult } = useResult()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)
  const controllerRef = useRef<AbortController | null>(null)

  useEffect(() => () => controllerRef.current?.abort(), [])

  const run = useCallback(
    async (...args: A): Promise<boolean> => {
      controllerRef.current?.abort()
      const controller = new AbortController()
      controllerRef.current = controller
      setLoading(true)
      setError(null)
      try {
        const result = await call(...args, controller.signal)
        if (controller.signal.aborted) return false
        setResult(result)
        router.push('/result')
        return true
      } catch (caught) {
        if (controller.signal.aborted) return false
        setError(caught instanceof ApiError ? caught : new ApiError(0, 'UNKNOWN', 'Something went wrong. Please try again.'))
        return false
      } finally {
        if (!controller.signal.aborted) setLoading(false)
      }
    },
    [call, router, setResult],
  )

  return { loading, error, run, clearError: () => setError(null) }
}
