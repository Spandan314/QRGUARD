import { afterEach, describe, expect, it, jest } from '@jest/globals'
import { Platform } from 'react-native'
import { jsonResponse, maliciousUrl } from '../test/fixtures'
import { api, ApiError } from './api'

const realFetch = global.fetch
afterEach(() => {
  global.fetch = realFetch
  jest.useRealTimers()
})

function stubFetch(impl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  const mock = jest.fn(impl)
  global.fetch = mock as unknown as typeof fetch
  return mock
}

describe('api client', () => {
  it('posts JSON without cookies', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    const result = await api.analyzeUrl('http://x.test')
    expect(result.risk_level).toBe('MALICIOUS')
    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(String(url)).toMatch(/\/api\/analyze\/url$/)
    expect(init?.credentials).toBe('omit')
    expect(init?.body).toBe(JSON.stringify({ url: 'http://x.test', save_to_history: false }))
  })

  it('uploads a picked image as multipart form data to the combined QR + text endpoint', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    await api.analyzeImage({ uri: 'file:///tmp/img.jpg', name: 'image.jpg', mimeType: 'image/jpeg' })
    const init = fetchMock.mock.calls[0]?.[1]
    expect(init?.body).toBeInstanceOf(FormData)
    // fetch must set the multipart boundary itself
    expect((init?.headers as Record<string, string>)['Content-Type']).toBeUndefined()
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/screenshot$/)
  })

  it('on the web build, uploads the picked image as a real file (not "[object Object]")', async () => {
    const original = Platform.OS
    Object.defineProperty(Platform, 'OS', { value: 'web', configurable: true })
    try {
      const fetchMock = stubFetch(async (input) =>
        String(input).startsWith('blob:') ? new Response(new Blob(['jpeg-bytes'])) : jsonResponse(maliciousUrl),
      )
      await api.analyzeImage({ uri: 'blob:http://localhost/1234', name: 'image.jpg', mimeType: 'image/jpeg' })
      expect(String(fetchMock.mock.calls[0]?.[0])).toBe('blob:http://localhost/1234') // read locally first
      const body = fetchMock.mock.calls[1]?.[1]?.body as FormData
      const file = body.get('file') as File
      expect(file).toBeInstanceOf(Blob)
      expect([file.name, file.type, await file.text()]).toEqual(['image.jpg', 'image/jpeg', 'jpeg-bytes'])
      expect(body.get('save_to_history')).toBe('false')
    } finally {
      Object.defineProperty(Platform, 'OS', { value: original, configurable: true })
    }
  })

  it('tells an interrupted upload apart from being offline', async () => {
    const image = { uri: 'file:///tmp/img.jpg', name: 'image.jpg', mimeType: 'image/jpeg' }
    // The upload fails, but the server answers its health check: the upload was cut off.
    stubFetch(async (input) => {
      if (String(input).endsWith('/api/health')) return jsonResponse({ status: 'ok', engine_version: '1', components: { api: 'ok' } })
      throw new TypeError('Network request failed')
    })
    await expect(api.analyzeImage(image)).rejects.toMatchObject({ code: 'UPLOAD_FAILED' })
    // Nothing answers: the phone cannot reach the server at all.
    stubFetch(async () => {
      throw new TypeError('Network request failed')
    })
    await expect(api.analyzeImage(image)).rejects.toMatchObject({ code: 'NETWORK_ERROR' })
  })

  it('retries an interrupted upload once, with a fresh form, and succeeds', async () => {
    const image = { uri: 'file:///tmp/img.jpg', name: 'image.jpg', mimeType: 'image/jpeg' }
    let uploads = 0
    const fetchMock = stubFetch(async (input) => {
      if (String(input).endsWith('/api/health')) return jsonResponse({ status: 'ok', engine_version: '1', components: { api: 'ok' } })
      uploads += 1
      if (uploads === 1) throw new TypeError('Network request failed') // cut off, e.g. while the server wakes up
      return jsonResponse(maliciousUrl)
    })
    await expect(api.analyzeImage(image)).resolves.toMatchObject({ risk_level: 'MALICIOUS' })
    expect(uploads).toBe(2)
    const forms = fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/api/analyze/screenshot')).map(([, init]) => init?.body)
    expect(forms[0]).not.toBe(forms[1]) // a request body is never reused
  })

  it('does not retry when the phone is offline', async () => {
    let uploads = 0
    stubFetch(async () => {
      uploads += 1
      throw new TypeError('Network request failed')
    })
    await expect(api.analyzeImage({ uri: 'f', name: 'i.jpg', mimeType: 'image/jpeg' })).rejects.toMatchObject({ code: 'NETWORK_ERROR' })
    expect(uploads).toBe(2) // one upload + one health check, no second upload
  })

  it('explains hosting-platform errors and oversized uploads', async () => {
    stubFetch(async () => new Response('<html>Bad gateway</html>', { status: 502 }))
    await expect(api.analyzeUrl('x')).rejects.toMatchObject({ code: 'SERVER_UNAVAILABLE' })
    stubFetch(async () => new Response('<html>Too large</html>', { status: 413 }))
    await expect(api.analyzeImage({ uri: 'f', name: 'i.jpg', mimeType: 'image/jpeg' })).rejects.toMatchObject({
      code: 'PAYLOAD_TOO_LARGE',
    })
  })

  it('sends camera content with source camera', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    await api.analyzeQrContent('upi://pay?pa=a@b')
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ content: 'upi://pay?pa=a@b', source: 'camera', save_to_history: false }))
  })

  it('maps the error envelope, non-JSON errors and unreadable bodies', async () => {
    stubFetch(async () => jsonResponse({ error: { code: 'NO_QR_FOUND', message: 'No QR code.', request_id: 'r' } }, 422))
    await expect(api.analyzeQrContent('x')).rejects.toMatchObject({ code: 'NO_QR_FOUND', status: 422, requestId: 'r' })
    stubFetch(async () => new Response('<html>', { status: 404 }))
    await expect(api.analyzeUrl('x')).rejects.toMatchObject({ code: 'HTTP_ERROR' })
    stubFetch(async () => new Response('nope', { status: 200 }))
    await expect(api.analyzeUrl('x')).rejects.toMatchObject({ code: 'BAD_RESPONSE' })
  })

  it('reports network errors and timeouts', async () => {
    stubFetch(async () => {
      throw new TypeError('Network request failed')
    })
    await expect(api.analyzeMessage('hi')).rejects.toMatchObject({ code: 'NETWORK_ERROR' })

    jest.useFakeTimers()
    stubFetch(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
    )
    const pending = api.health()
    jest.advanceTimersByTime(10_001)
    await expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' })
  })

  it('passes a caller abort through', async () => {
    stubFetch(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
    )
    const controller = new AbortController()
    const pending = api.analyzeUrl('x', {}, controller.signal)
    controller.abort()
    await expect(pending).rejects.not.toBeInstanceOf(ApiError)
  })
})
