import { maliciousUrl, jsonResponse } from '../test/fixtures'
import { api, ApiError, apiBaseUrl } from './api'

function stubFetch(impl: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>) {
  const fetchMock = vi.fn(impl)
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('api client', () => {
  it('uses the configured base URL without a trailing slash', () => {
    vi.stubEnv('VITE_API_BASE_URL', 'https://api.example.test///')
    expect(apiBaseUrl()).toBe('https://api.example.test')
    vi.unstubAllEnvs()
  })

  it('posts JSON without cookies and returns the result', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    const result = await api.analyzeUrl('http://x.test')
    expect(result.risk_level).toBe('MALICIOUS')
    const [url, init] = fetchMock.mock.calls[0] ?? []
    expect(String(url)).toMatch(/\/api\/analyze\/url$/)
    expect(init?.credentials).toBe('omit')
    expect(init?.body).toBe(JSON.stringify({ url: 'http://x.test', save_to_history: false }))
  })

  it('sends files as multipart form data', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    const file = new File(['png'], 'shot.png', { type: 'image/png' })
    await api.analyzeScreenshot(file)
    const init = fetchMock.mock.calls[0]?.[1]
    expect(init?.body).toBeInstanceOf(FormData)
    expect((init?.body as FormData).get('file')).toBeInstanceOf(File)
  })

  it('sends decoded QR content as a camera scan', async () => {
    const fetchMock = stubFetch(async () => jsonResponse(maliciousUrl))
    await api.analyzeQrContent('upi://pay?pa=a@b')
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ content: 'upi://pay?pa=a@b', source: 'camera', save_to_history: false }),
    )
  })

  it('turns the backend error envelope into an ApiError', async () => {
    stubFetch(async () =>
      jsonResponse({ error: { code: 'INVALID_URL', message: 'The link has no domain name.', request_id: 'r1' } }, 400),
    )
    await expect(api.analyzeUrl('http://')).rejects.toMatchObject({
      name: 'ApiError',
      status: 400,
      code: 'INVALID_URL',
      message: 'The link has no domain name.',
      requestId: 'r1',
    })
  })

  it('handles non-JSON errors and unreadable success bodies', async () => {
    stubFetch(async () => new Response('<html>502</html>', { status: 502 }))
    await expect(api.analyzeUrl('x')).rejects.toMatchObject({ code: 'HTTP_ERROR', status: 502 })
    stubFetch(async () => new Response('not json', { status: 200 }))
    await expect(api.analyzeUrl('x')).rejects.toMatchObject({ code: 'BAD_RESPONSE' })
  })

  it('reports network failures', async () => {
    stubFetch(async () => {
      throw new TypeError('Failed to fetch')
    })
    await expect(api.analyzeMessage('hi')).rejects.toMatchObject({ code: 'NETWORK_ERROR' })
  })

  it('times out slow requests', async () => {
    vi.useFakeTimers()
    stubFetch(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        }),
    )
    const pending = api.health()
    const assertion = expect(pending).rejects.toMatchObject({ code: 'TIMEOUT' })
    await vi.advanceTimersByTimeAsync(10_001)
    await assertion
    vi.useRealTimers()
  })

  it('passes a caller abort through unchanged', async () => {
    stubFetch(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
        }),
    )
    const controller = new AbortController()
    const pending = api.analyzeUrl('x', {}, controller.signal)
    controller.abort()
    await expect(pending).rejects.not.toBeInstanceOf(ApiError)
  })
})
