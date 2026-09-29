// Builds QR payloads in the browser, so private data (such as a Wi-Fi password) never leaves the
// device. Same formats and escaping rules as the backend generator (POST /api/generate/qr).

export type QrKind = 'text' | 'url' | 'wifi' | 'email' | 'phone'
export type WifiSecurity = 'WPA' | 'WPA3' | 'WEP' | 'nopass'

export interface QrInput {
  text?: string
  url?: string
  ssid?: string
  password?: string
  security?: WifiSecurity
  hidden?: boolean
  to?: string
  subject?: string
  body?: string
  number?: string
}

export class PayloadError extends Error {}

const EMAIL_RE = /^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}$/
const PHONE_RE = /^\+?[0-9][0-9 ()-]{2,19}$/

/** Escape the characters that have a special meaning in WIFI: payloads. */
export function escapeWifi(value: string): string {
  return value.replace(/([\\;,:"])/g, '\\$1')
}

export function buildPayload(kind: QrKind, input: QrInput): string {
  switch (kind) {
    case 'text': {
      const text = input.text ?? ''
      if (text.length < 1 || text.length > 1000) throw new PayloadError('Text must be 1 to 1000 characters.')
      return text
    }
    case 'url': {
      const raw = (input.url ?? '').trim()
      let parsed: URL
      try {
        parsed = new URL(raw)
      } catch {
        throw new PayloadError('Enter a complete link starting with http:// or https://')
      }
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        throw new PayloadError('Only http:// and https:// links can be turned into a QR code.')
      }
      if (!parsed.hostname) throw new PayloadError('The link has no domain name.')
      return parsed.href
    }
    case 'wifi': {
      const ssid = input.ssid ?? ''
      const password = input.password ?? ''
      const security = input.security ?? 'WPA'
      if (ssid.length < 1 || ssid.length > 32) throw new PayloadError('The network name must be 1 to 32 characters.')
      if (security === 'nopass' && password) throw new PayloadError('An open network cannot have a password.')
      if ((security === 'WPA' || security === 'WPA3') && (password.length < 8 || password.length > 63)) {
        throw new PayloadError('A WPA password must be 8 to 63 characters.')
      }
      if (security === 'WEP' && !password) throw new PayloadError('A WEP network needs a password.')
      const type = security === 'WPA3' ? 'SAE' : security
      const parts = [`T:${type}`, `S:${escapeWifi(ssid)}`]
      if (password) parts.push(`P:${escapeWifi(password)}`)
      if (input.hidden) parts.push('H:true')
      return `WIFI:${parts.join(';')};;`
    }
    case 'email': {
      const to = (input.to ?? '').trim()
      if (!EMAIL_RE.test(to)) throw new PayloadError('Enter a valid e-mail address.')
      const subject = input.subject ?? ''
      const body = input.body ?? ''
      if (subject.length > 200 || body.length > 1000) throw new PayloadError('Subject or message is too long.')
      const query = [
        ['subject', subject],
        ['body', body],
      ]
        .filter(([, value]) => value)
        .map(([key, value]) => `${key}=${encodeURIComponent(value ?? '')}`)
        .join('&')
      return `mailto:${to}${query ? `?${query}` : ''}`
    }
    case 'phone': {
      const number = (input.number ?? '').trim()
      if (!PHONE_RE.test(number)) throw new PayloadError('Enter a phone number (digits, spaces, +, - or brackets).')
      return `tel:${number.replace(/[ ()-]/g, '')}`
    }
  }
}
