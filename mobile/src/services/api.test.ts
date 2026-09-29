import { afterEach, describe, expect, it, jest } from '@jest/globals'
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

  it('uploads a picked image as multipart form data', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    await api.analyzeQrImage({ uri: 'file:///tmp/qr.png', name: 'qr.png', mimeType: 'image/png' })
    const init = fetchMock.mock.calls[0]?.[1]
    expect(init?.body).toBeInstanceOf(FormData)
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/qr$/)
  })

  it('sends camera content with source camera', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    await api.analyzeQrContent('upi://pay?pa=a@b')
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ content: 'upi://pay?pa=a@b', source: 'camera', save_to_history: false }))
  })

  it('maps the error envelope, non-JSON errors and unreadable bodies', async () => {
    stubFetch(async () => jsonResponse({ error: { code: 'NO_QR_FOUND', message: 'No QR code.', request_id: 'r' } }, 422))
    await expect(api.analyzeQrContent('x')).rejects.toMatchObject({ code: 'NO_QR_FOUND', status: 422, requestId: 'r' })
    stubFetch(async () => new Response('<html>', { status: 503 }))
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
