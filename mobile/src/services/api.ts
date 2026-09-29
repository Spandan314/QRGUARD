import { API_BASE_URL } from '../constants/config'
import type { AnalysisResult, ApiErrorBody, HealthResponse } from '../types/api'

// The backend does every check; this module only sends the input and returns the answer.
const DEFAULT_TIMEOUT_MS = 45_000

export interface PickedImage {
  uri: string
  name: string
  mimeType: string
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

async function request<T>(path: string, init: RequestInit, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort)
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, { ...init, signal: controller.signal, credentials: 'omit' })
  } catch (error) {
    if (signal?.aborted) throw error
    if (timedOut) throw new ApiError(0, 'TIMEOUT', 'The check took too long. Please try again.')
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the QRGUARD server. Check your internet connection.')
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
    if (isErrorBody(body)) throw new ApiError(response.status, body.error.code, body.error.message, body.error.request_id)
    throw new ApiError(response.status, 'HTTP_ERROR', `The server answered with an error (${response.status}).`)
  }
  if (body === null) throw new ApiError(response.status, 'BAD_RESPONSE', 'The server sent an unreadable answer.')
  return body as T
}

function postJson<T>(path: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(
    path,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
    signal,
  )
}

function postImage<T>(path: string, image: PickedImage, signal?: AbortSignal): Promise<T> {
  const form = new FormData()
  // React Native's FormData accepts a { uri, name, type } descriptor for files.
  form.append('file', { uri: image.uri, name: image.name, type: image.mimeType } as unknown as Blob)
  return request<T>(path, { method: 'POST', body: form }, signal)
}

export const api = {
  health: (signal?: AbortSignal) => request<HealthResponse>('/api/health', { method: 'GET' }, signal, 10_000),
  analyzeUrl: (url: string, signal?: AbortSignal) => postJson<AnalysisResult>('/api/analyze/url', { url }, signal),
  analyzeMessage: (text: string, signal?: AbortSignal) =>
    postJson<AnalysisResult>('/api/analyze/message', { text }, signal),
  analyzeScreenshot: (image: PickedImage, signal?: AbortSignal) =>
    postImage<AnalysisResult>('/api/analyze/screenshot', image, signal),
  analyzeQrImage: (image: PickedImage, signal?: AbortSignal) => postImage<AnalysisResult>('/api/analyze/qr', image, signal),
  analyzeQrContent: (content: string, signal?: AbortSignal) =>
    postJson<AnalysisResult>('/api/analyze/qr', { content, source: 'camera' }, signal),
}
