import type { AnalysisResult, ApiErrorBody, HealthResponse } from '../types/api'

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
  let response: Response
  try {
    response = await fetch(`${apiBaseUrl()}${path}`, {
      ...init,
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

function postJson<T>(path: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(
    path,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
    signal,
  )
}

function postFile<T>(path: string, file: File, signal?: AbortSignal): Promise<T> {
  const form = new FormData()
  form.append('file', file)
  return request<T>(path, { method: 'POST', body: form }, signal)
}

export const api = {
  health: (signal?: AbortSignal) => request<HealthResponse>('/api/health', { method: 'GET' }, signal, 10_000),
  analyzeUrl: (url: string, signal?: AbortSignal) =>
    postJson<AnalysisResult>('/api/analyze/url', { url }, signal),
  analyzeMessage: (text: string, signal?: AbortSignal) =>
    postJson<AnalysisResult>('/api/analyze/message', { text }, signal),
  analyzeScreenshot: (file: File, signal?: AbortSignal) =>
    postFile<AnalysisResult>('/api/analyze/screenshot', file, signal),
  analyzeQrImage: (file: File, signal?: AbortSignal) =>
    postFile<AnalysisResult>('/api/analyze/qr', file, signal),
  analyzeQrContent: (content: string, signal?: AbortSignal) =>
    postJson<AnalysisResult>('/api/analyze/qr', { content, source: 'camera' }, signal),
}
