import { createContext, useContext, useMemo, useState, type ReactNode } from 'react'
import type { AnalysisResult } from '../types/api'

// The result travels through context, not route params: it is large and params can end up in logs.
interface ResultState {
  result: AnalysisResult | null
  setResult: (result: AnalysisResult | null) => void
}

const ResultContext = createContext<ResultState | null>(null)

export function ResultProvider({ children }: { children: ReactNode }) {
  const [result, setResult] = useState<AnalysisResult | null>(null)
  const value = useMemo(() => ({ result, setResult }), [result])
  return <ResultContext.Provider value={value}>{children}</ResultContext.Provider>
}

export function useResult(): ResultState {
  const value = useContext(ResultContext)
  if (!value) throw new Error('useResult must be used inside ResultProvider')
  return value
}
