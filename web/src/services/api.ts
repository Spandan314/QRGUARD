import type {
  AdminReport,
  AdminStats,
  AnalysisResult,
  ApiErrorBody,
  HealthResponse,
  HistoryItem,
  HistoryPage,
  Profile,
  ReportKind,
} from '../types/api'

// The backend does every check. This module only sends the user's input and returns the answer.
const DEFAULT_TIMEOUT_MS = 45_000 // OCR plus redirect and threat-intel checks can take a while

export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024
export const ACCEPTED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/webp']

export function apiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_BASE_URL as string | undefined
  return (configured || 'http://localhost:5000').replace(/\/+$/, '')
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly requestId: string | undefined

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.requestId = requestId
  }
}

/** Set by AuthProvider: returns a fresh ID token for the signed-in user, or null. */
type TokenProvider = () => Promise<string | null>
let tokenProvider: TokenProvider = async () => null

export function setTokenProvider(provider: TokenProvider): void {
  tokenProvider = provider
}

function isErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== 'object' || value === null || !('error' in value)) return false
  const error = (value as { error: unknown }).error
  return typeof error === 'object' && error !== null && 'code' in error && 'message' in error
}

async function request<T>(
  path: string,
  init: RequestInit,
  signal?: AbortSignal,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(new DOMException('timeout', 'TimeoutError')), timeoutMs)
  const onAbort = () => controller.abort(signal?.reason)
  signal?.addEventListener('abort', onAbort)
  const headers = new Headers(init.headers)
  let response: Response
  try {
    const token = await tokenProvider().catch(() => null)
    if (token) headers.set('Authorization', `Bearer ${token}`)
    if (controller.signal.aborted) throw controller.signal.reason ?? new DOMException('aborted', 'AbortError')
    response = await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
      headers,
      signal: controller.signal,
      credentials: 'omit', // no cookies: the API uses Authorization headers only
      referrerPolicy: 'no-referrer',
    })
  } catch (error) {
    if (signal?.aborted) throw error
    if (controller.signal.aborted) {
      throw new ApiError(0, 'TIMEOUT', 'The check took too long. Please try again.')
    }
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the QRGUARD server. Check your connection.')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }

  if (response.status === 204) return undefined as T
  let body: unknown
  try {
    body = await response.json()
  } catch {
    body = null
  }
  if (!response.ok) {
    if (isErrorBody(body)) {
      throw new ApiError(response.status, body.error.code, body.error.message, body.error.request_id)
    }
    throw new ApiError(response.status, 'HTTP_ERROR', `The server answered with an error (${response.status}).`)
  }
  if (body === null) {
    throw new ApiError(response.status, 'BAD_RESPONSE', 'The server sent an unreadable answer.')
  }
  return body as T
}

function sendJson<T>(method: string, path: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(
    path,
    { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
    signal,
  )
}

function postFile<T>(path: string, file: File, save: boolean, signal?: AbortSignal): Promise<T> {
  const form = new FormData()
  form.append('file', file)
  form.append('save_to_history', save ? 'true' : 'false')
  return request<T>(path, { method: 'POST', body: form }, signal)
}

export interface AnalyzeOptions {
  save?: boolean
}

export const api = {
  health: (signal?: AbortSignal) => request<HealthResponse>('/api/health', { method: 'GET' }, signal, 10_000),
  analyzeUrl: (url: string, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    sendJson<AnalysisResult>('POST', '/api/analyze/url', { url, save_to_history: options.save ?? false }, signal),
  analyzeMessage: (text: string, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    sendJson<AnalysisResult>('POST', '/api/analyze/message', { text, save_to_history: options.save ?? false }, signal),
  analyzeScreenshot: (file: File, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    postFile<AnalysisResult>('/api/analyze/screenshot', file, options.save ?? false, signal),
  analyzeQrImage: (file: File, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    postFile<AnalysisResult>('/api/analyze/qr', file, options.save ?? false, signal),
  analyzeQrContent: (content: string, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    sendJson<AnalysisResult>(
      'POST',
      '/api/analyze/qr',
      { content, source: 'camera', save_to_history: options.save ?? false },
      signal,
    ),

  // ----- signed-in features ---------------------------------------------------------------------
  history: (cursor: string | null = null, limit = 20, signal?: AbortSignal) => {
    const query = new URLSearchParams({ limit: String(limit) })
    if (cursor) query.set('cursor', cursor)
    return request<HistoryPage>(`/api/history?${query}`, { method: 'GET' }, signal)
  },
  historyItem: (id: string, signal?: AbortSignal) =>
    request<HistoryItem>(`/api/history/${encodeURIComponent(id)}`, { method: 'GET' }, signal),
  deleteHistoryItem: (id: string) =>
    request<undefined>(`/api/history/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  deleteAllHistory: () => request<{ deleted: number }>('/api/history', { method: 'DELETE' }),
  me: (signal?: AbortSignal) => request<Profile>('/api/me', { method: 'GET' }, signal),
  updateMe: (saveHistory: boolean) => sendJson<Profile>('PATCH', '/api/me', { save_history: saveHistory }),
  deleteMe: () =>
    request<{ deleted_scans: number; anonymised_reports: number; account_deleted: boolean }>('/api/me', {
      method: 'DELETE',
    }),
  report: (reportedAs: ReportKind, note: string, scanId?: string) =>
    sendJson<{ id: string }>('POST', '/api/reports', {
      reported_as: reportedAs,
      note,
      ...(scanId ? { scan_id: scanId } : {}),
    }),
  adminStats: (days = 30, signal?: AbortSignal) =>
    request<AdminStats>(`/api/admin/stats?days=${days}`, { method: 'GET' }, signal),
  adminReports: (status: 'open' | 'reviewed', signal?: AbortSignal) =>
    request<{ items: AdminReport[] }>(`/api/admin/reports?status=${status}`, { method: 'GET' }, signal),
  adminUpdateReport: (id: string, status: 'open' | 'reviewed') =>
    sendJson<{ id: string; status: string }>('PATCH', `/api/admin/reports/${encodeURIComponent(id)}`, { status }),
}
