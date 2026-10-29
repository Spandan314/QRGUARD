import { File, UploadType } from 'expo-file-system'
import { Platform } from 'react-native'
import { API_BASE_URL } from '../constants/config'
import type {
  AnalysisResult,
  ApiErrorBody,
  HealthResponse,
  HistoryItem,
  HistoryPage,
  Profile,
  ReportKind,
} from '../types/api'

// The backend does every check; this module only sends the input and returns the answer.
const DEFAULT_TIMEOUT_MS = 45_000
// Images: upload on mobile data + OCR on a small (free-tier) server, possibly after a cold start.
const UPLOAD_TIMEOUT_MS = 90_000
const HEALTH_PROBE_MS = 10_000

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

/** Set by AuthProvider: a fresh ID token for the signed-in user, or null. */
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

async function request<T>(path: string, init: RequestInit, signal?: AbortSignal, timeoutMs = DEFAULT_TIMEOUT_MS): Promise<T> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, timeoutMs)
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort)
  const headers: Record<string, string> = { ...((init.headers as Record<string, string> | undefined) ?? {}) }
  let response: Response
  try {
    const token = await tokenProvider().catch(() => null)
    if (token) headers.Authorization = `Bearer ${token}`
    if (controller.signal.aborted) throw new Error('aborted')
    response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers, signal: controller.signal, credentials: 'omit' })
  } catch (error) {
    if (signal?.aborted) throw error
    if (timedOut) throw new ApiError(0, 'TIMEOUT', 'The check took too long. Please try again.')
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the QRGUARD server. Check your internet connection.')
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
  return answer<T>(response.status, body)
}

/** The parsed JSON answer, or the ApiError that matches the status and body. */
function answer<T>(status: number, body: unknown): T {
  const ok = status >= 200 && status < 300
  if (!ok) {
    if (isErrorBody(body)) throw new ApiError(status, body.error.code, body.error.message, body.error.request_id)
    if (status === 413) {
      throw new ApiError(413, 'PAYLOAD_TOO_LARGE', 'The image is too large for the server (maximum 5 MB).')
    }
    if (status >= 500) {
      // Not a QRGUARD answer: the hosting platform's own page while the server starts or restarts.
      throw new ApiError(status, 'SERVER_UNAVAILABLE', 'The QRGUARD server is starting up or temporarily unavailable.')
    }
    throw new ApiError(status, 'HTTP_ERROR', `The server answered with an error (${status}).`)
  }
  if (body === null) throw new ApiError(status, 'BAD_RESPONSE', 'The server sent an unreadable answer.')
  return body as T
}

function sendJson<T>(method: string, path: string, payload: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>(
    path,
    { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
    signal,
  )
}

/** True when the server answers its health check, i.e. it is reachable from this phone now. */
async function serverReachable(): Promise<boolean> {
  try {
    await request<HealthResponse>('/api/health', { method: 'GET' }, undefined, HEALTH_PROBE_MS)
    return true
  } catch {
    return false
  }
}

// An upload cut off while the server is up is usually the free server waking up or restarting a
// worker; one automatic retry after a short pause fixes most of these without bothering the user.
export const UPLOAD_RETRY_DELAY_MS = 1500

/** Web only: a browser's FormData needs a real Blob for the picked image. */
async function imageForm(image: PickedImage, save: boolean): Promise<FormData> {
  const form = new FormData()
  // The picked image is a local blob:/data: URI, so it is read in the browser (no network request).
  // The Content-Type header (with the multipart boundary) is set by fetch itself.
  const blob = await (await fetch(image.uri)).blob()
  form.append('file', new Blob([blob], { type: image.mimeType }), image.name)
  form.append('save_to_history', save ? 'true' : 'false')
  return form
}

/**
 * Android and iOS: the file is uploaded by Expo's native uploader (expo-file-system), which streams
 * it from disk as a standard multipart form. React Native's fetch with a { uri } form part failed on
 * Android phones ("Network request failed") although the server accepts the same form from other
 * clients, so phones do not use it for images.
 */
async function uploadNative<T>(path: string, image: PickedImage, save: boolean, signal?: AbortSignal): Promise<T> {
  const controller = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => {
    timedOut = true
    controller.abort()
  }, UPLOAD_TIMEOUT_MS)
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort)
  let status: number
  let text: string
  try {
    const token = await tokenProvider().catch(() => null)
    const result = await new File(image.uri).upload(`${API_BASE_URL}${path}`, {
      httpMethod: 'POST',
      uploadType: UploadType.MULTIPART,
      fieldName: 'file',
      mimeType: image.mimeType,
      parameters: { save_to_history: save ? 'true' : 'false' },
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      signal: controller.signal,
    })
    status = result.status
    text = result.body
  } catch (error) {
    if (signal?.aborted) throw error
    if (timedOut) throw new ApiError(0, 'TIMEOUT', 'The check took too long. Please try again.')
    throw new ApiError(0, 'NETWORK_ERROR', 'Cannot reach the QRGUARD server. Check your internet connection.')
  } finally {
    clearTimeout(timer)
    signal?.removeEventListener('abort', onAbort)
  }
  let body: unknown = null
  try {
    body = text ? JSON.parse(text) : null
  } catch {
    body = null
  }
  return answer<T>(status, body)
}

async function sendImage<T>(path: string, image: PickedImage, save: boolean, signal?: AbortSignal): Promise<T> {
  if (Platform.OS !== 'web') return uploadNative<T>(path, image, save, signal)
  // A fresh form for every attempt: a request body cannot be sent twice.
  return request<T>(path, { method: 'POST', body: await imageForm(image, save) }, signal, UPLOAD_TIMEOUT_MS)
}

async function postImage<T>(path: string, image: PickedImage, save: boolean, signal?: AbortSignal): Promise<T> {
  for (let attempt = 1; ; attempt++) {
    try {
      return await sendImage<T>(path, image, save, signal)
    } catch (error) {
      // "Network request failed" during an upload does not always mean the phone is offline: the
      // connection can also be cut off mid-upload. Ask the server directly to tell which it was.
      const cutOff = error instanceof ApiError && error.code === 'NETWORK_ERROR' && !signal?.aborted
      if (!cutOff || !(await serverReachable())) throw error
      if (attempt >= 2) {
        throw new ApiError(
          0,
          'UPLOAD_FAILED',
          'The server is reachable, but the image upload was interrupted before the check could finish.',
        )
      }
      await new Promise((resolve) => setTimeout(resolve, UPLOAD_RETRY_DELAY_MS))
      if (signal?.aborted) throw error
    }
  }
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
  /** Screenshots and photos of QR codes: the server decodes QR codes AND reads the text. */
  analyzeImage: (image: PickedImage, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    postImage<AnalysisResult>('/api/analyze/screenshot', image, options.save ?? false, signal),
  analyzeQrContent: (content: string, options: AnalyzeOptions = {}, signal?: AbortSignal) =>
    sendJson<AnalysisResult>(
      'POST',
      '/api/analyze/qr',
      { content, source: 'camera', save_to_history: options.save ?? false },
      signal,
    ),

  // ----- signed-in features ---------------------------------------------------------------------
  history: (cursor: string | null = null, limit = 20, signal?: AbortSignal) =>
    request<HistoryPage>(
      `/api/history?limit=${limit}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`,
      { method: 'GET' },
      signal,
    ),
  historyItem: (id: string, signal?: AbortSignal) =>
    request<HistoryItem>(`/api/history/${encodeURIComponent(id)}`, { method: 'GET' }, signal),
  deleteHistoryItem: (id: string) => request<undefined>(`/api/history/${encodeURIComponent(id)}`, { method: 'DELETE' }),
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
}
