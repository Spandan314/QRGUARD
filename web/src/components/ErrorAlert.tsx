import type { ApiError } from '../services/api'

const HINTS: Record<string, string> = {
  NETWORK_ERROR: 'The server may be starting up (this can take up to a minute on the free tier).',
  RATE_LIMITED: 'You have made many checks in a short time. Please wait a minute.',
  OCR_UNAVAILABLE: 'Text recognition is not available on the server right now.',
  NO_TEXT_FOUND: 'Try a sharper screenshot where the message text is clearly visible.',
  NO_QR_FOUND: 'Make sure the QR code is sharp, fully visible and not too small.',
  TIMEOUT: 'The server or a reputation service was slow. Please try again.',
  INVALID_TOKEN: 'Your session has expired. Sign out and sign in again on the Account page.',
  AUTH_REQUIRED: 'Please sign in on the Account page.',
  SERVICE_UNAVAILABLE: 'This feature is temporarily unavailable on the server.',
  UNSUPPORTED_MEDIA_TYPE: 'Please use a PNG, JPEG or WEBP image.',
  INVALID_URL: 'Check that the link is complete, for example https://example.com/page.',
  OCR_BUSY: 'The server is busy reading other screenshots. Please try again in a moment.',
}

export function ErrorAlert({ error }: { error: ApiError }) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-red-300 bg-red-50 p-4 text-sm text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-100"
    >
      <p className="font-semibold">Could not complete the check</p>
      <p className="mt-1">{error.message}</p>
      {HINTS[error.code] ? <p className="mt-1">{HINTS[error.code]}</p> : null}
      {error.requestId ? (
        <p className="mt-2 text-xs opacity-75">
          Request ID: <span className="font-mono">{error.requestId}</span>
        </p>
      ) : null}
    </div>
  )
}
