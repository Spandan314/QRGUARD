import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { jsonResponse, maliciousUrl, qrResult, screenshotResult } from '../test/fixtures'
import { renderRoute } from '../test/renderRoute'

function stubFetch(...responses: Response[]) {
  const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
    void _input
    void _init
    return responses.shift() ?? jsonResponse({}, 500)
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

const healthy = () =>
  jsonResponse({
    status: 'ok',
    engine_version: '0.1.0',
    components: {
      api: 'ok',
      ocr_engine: 'available',
      threat_intel: {
        enabled: true,
        providers: [
          { provider: 'local_feed', enabled: true, external: false },
          { provider: 'urlhaus', enabled: false, external: true },
        ],
      },
    },
  })

describe('dashboard', () => {
  it('shows the backend status from /api/health', async () => {
    stubFetch(healthy())
    renderRoute('/')
    const status = await screen.findByTestId('backend-status')
    await waitFor(() => expect(status).toHaveAttribute('data-state', 'ok'))
    expect(status).toHaveTextContent('Ready to check · 1 scam database connected')
    expect(screen.getByRole('link', { name: 'Link' })).toHaveAttribute('href', '/check/url')
  })

  it('waits for a sleeping server, retries, and only then says it cannot be reached, with "Try again"', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    try {
      const fetchMock = vi.fn(async () => Promise.reject(new TypeError('offline')))
      vi.stubGlobal('fetch', fetchMock)
      renderRoute('/')
      expect(await screen.findByText(/Starting the checker/)).toBeInTheDocument() // one failure is not "down"
      await act(async () => {
        await vi.advanceTimersByTimeAsync(95_000)
      })
      expect(await screen.findByText(/can’t reach the checker/)).toBeInTheDocument()
      const tries = fetchMock.mock.calls.length
      expect(tries).toBeGreaterThan(5) // it kept retrying while the server could be waking up
      await userEvent.click(screen.getByRole('button', { name: 'Try again' }))
      await waitFor(() => expect(fetchMock.mock.calls.length).toBeGreaterThan(tries))
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('URL check', () => {
  it('sends the link and shows the explained result', async () => {
    const fetchMock = stubFetch(jsonResponse(maliciousUrl))
    renderRoute('/check/url')
    const button = screen.getByRole('button', { name: 'Check link' })
    expect(button).toBeDisabled()
    await userEvent.type(screen.getByLabelText('Link'), '  http://sbi.co.in.kyc-verify.xyz/login ')
    await userEvent.click(button)
    expect(await screen.findByRole('article', { name: 'Analysis result' })).toHaveTextContent('MALICIOUS')
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ url: 'http://sbi.co.in.kyc-verify.xyz/login', save_to_history: false }),
    )
  })

  it('shows backend errors with the request id', async () => {
    stubFetch(jsonResponse({ error: { code: 'RATE_LIMITED', message: 'Too many requests.', request_id: 'rid9' } }, 429))
    renderRoute('/check/url')
    await userEvent.type(screen.getByLabelText('Link'), 'x.test')
    await userEvent.click(screen.getByRole('button', { name: 'Check link' }))
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('Too many requests.')
    expect(alert).toHaveTextContent('Please wait a minute')
    expect(alert).toHaveTextContent('rid9')
  })
})

describe('message check', () => {
  it('counts characters and analyses the text', async () => {
    const fetchMock = stubFetch(jsonResponse({ ...maliciousUrl, input_type: 'message' }))
    renderRoute('/check/message')
    await userEvent.type(screen.getByLabelText('Message text'), 'Share your OTP')
    expect(screen.getByText('14 / 5000')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Check message' }))
    await screen.findByRole('article', { name: 'Analysis result' })
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ text: 'Share your OTP', save_to_history: false }))
  })
})

describe('screenshot check', () => {
  it('rejects unsupported and oversized files before uploading', async () => {
    const fetchMock = stubFetch()
    const { container } = renderRoute('/check/screenshot')
    const input = container.querySelector('input[type=file]') as HTMLInputElement
    await userEvent.upload(input, new File(['%PDF'], 'doc.pdf', { type: 'application/pdf' }), { applyAccept: false })
    expect(screen.getByRole('alert')).toHaveTextContent('PNG, JPEG or WEBP')
    const big = new File([new Uint8Array(5 * 1024 * 1024 + 1)], 'big.png', { type: 'image/png' })
    await userEvent.upload(input, big)
    expect(screen.getByRole('alert')).toHaveTextContent('limit is 5 MB')
    expect(screen.getByRole('button', { name: 'Check screenshot' })).toBeDisabled()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('uploads a screenshot and shows the OCR text', async () => {
    const fetchMock = stubFetch(jsonResponse(screenshotResult))
    const { container } = renderRoute('/check/screenshot')
    const input = container.querySelector('input[type=file]') as HTMLInputElement
    await userEvent.upload(input, new File(['png'], 'shot.png', { type: 'image/png' }))
    expect(screen.getByTestId('selected-file')).toHaveTextContent('shot.png')
    await userEvent.click(screen.getByRole('button', { name: 'Check screenshot' }))
    expect(await screen.findByTestId('ocr-details')).toHaveTextContent('BLOCKED')
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/screenshot$/)
  })

  it('shows a helpful hint when no text is found', async () => {
    stubFetch(jsonResponse({ error: { code: 'NO_TEXT_FOUND', message: 'No readable text was found.' } }, 422))
    const { container } = renderRoute('/check/screenshot')
    await userEvent.upload(container.querySelector('input[type=file]') as HTMLInputElement, new File(['p'], 'a.png', { type: 'image/png' }))
    await userEvent.click(screen.getByRole('button', { name: 'Check screenshot' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('sharper screenshot')
  })
})

describe('QR image check', () => {
  it('uploads the image and shows the decoded content', async () => {
    const fetchMock = stubFetch(jsonResponse(qrResult))
    const { container } = renderRoute('/check/qr')
    expect(screen.getByText(/always sends money/)).toBeInTheDocument()
    await userEvent.upload(container.querySelector('input[type=file]') as HTMLInputElement, new File(['p'], 'qr.png', { type: 'image/png' }))
    await userEvent.click(screen.getByRole('button', { name: 'Check QR code' }))
    expect(await screen.findByTestId('qr-details')).toHaveTextContent('upi://pay?pa=refund.desk9912@okdemo')
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/qr$/)
  })
})

describe('QR generator', () => {
  it('creates a Wi-Fi code in the browser without contacting the server', async () => {
    const fetchMock = stubFetch()
    renderRoute('/generate')
    await userEvent.click(screen.getByLabelText('Wi-Fi'))
    await userEvent.type(screen.getByLabelText('Network name (SSID)'), 'HomeNet')
    await userEvent.type(screen.getByLabelText('Password'), 'correct-horse-battery')
    await userEvent.click(screen.getByRole('button', { name: 'Create QR code' }))
    const image = await screen.findByAltText('Generated QR code')
    expect(image.getAttribute('src')).toMatch(/^data:image\/png;base64,/)
    expect(screen.getByRole('link', { name: 'Download SVG' }).getAttribute('href')).toMatch(/^data:image\/svg\+xml/)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('shows validation errors', async () => {
    stubFetch()
    renderRoute('/generate')
    await userEvent.type(screen.getByLabelText('Link to encode'), 'javascript:alert(1)')
    await userEvent.click(screen.getByRole('button', { name: 'Create QR code' }))
    expect(screen.getByRole('alert')).toHaveTextContent('Only http:// and https://')
  })

  it('switches between types', async () => {
    stubFetch()
    renderRoute('/generate')
    for (const [type, field] of [
      ['Text', 'Text to encode'],
      ['E-mail', 'E-mail address'],
      ['Phone', 'Phone number'],
    ] as const) {
      await userEvent.click(screen.getByRole('radio', { name: type }))
      expect(screen.getByLabelText(field)).toBeInTheDocument()
    }
    await userEvent.type(screen.getByLabelText('Phone number'), '+91 98765 43210')
    await userEvent.click(screen.getByRole('button', { name: 'Create QR code' }))
    expect(await screen.findByAltText('Generated QR code')).toBeInTheDocument()
  })
})

describe('static pages and routing', () => {
  it.each([
    ['/tips', 'Safety tips'],
    ['/about', 'About QRGUARD'],
    ['/does-not-exist', 'Page not found'],
  ])('renders %s', (path, heading) => {
    stubFetch()
    renderRoute(path)
    expect(screen.getByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
  })

  it('marks the active navigation link', async () => {
    stubFetch()
    renderRoute('/tips')
    await waitFor(() => expect(screen.getByRole('link', { name: 'Safety tips' })).toHaveAttribute('aria-current', 'page'))
    expect(screen.getByRole('link', { name: 'Check anything' })).not.toHaveAttribute('aria-current')
  })
})

describe('header', () => {
  it('shows every page on the main bar, with no hidden menu', async () => {
    stubFetch(healthy())
    renderRoute('/')
    const nav = screen.getByRole('navigation', { name: 'Main' })
    const pages = { 'Check anything': '/', Link: '/check/url', Message: '/check/message', 'QR code': '/check/qr', Screenshot: '/check/screenshot', 'Make a QR': '/generate', History: '/history', 'Safety tips': '/tips', About: '/about' }
    for (const [name, href] of Object.entries(pages)) {
      const link = within(nav).getByRole('link', { name })
      expect(link).toBeVisible()
      expect(link).toHaveAttribute('href', href)
    }
    expect(screen.queryByRole('button', { name: 'More' })).toBeNull()
  })

  it('theme toggle switches the theme, says what it will do, and remembers the choice', async () => {
    stubFetch(healthy())
    localStorage.removeItem('qrguard-theme')
    renderRoute('/')
    const toggle = screen.getByTestId('theme-toggle')
    const before = document.documentElement.getAttribute('data-theme')
    expect(['light', 'dark']).toContain(before)
    const after = before === 'dark' ? 'light' : 'dark'
    expect(toggle).toHaveAccessibleName(`Switch to ${after} theme`)
    await userEvent.click(toggle)
    expect(document.documentElement.getAttribute('data-theme')).toBe(after)
    expect(localStorage.getItem('qrguard-theme')).toBe(after)
    expect(toggle).toHaveAccessibleName(`Switch to ${before} theme`)
    localStorage.removeItem('qrguard-theme')
  })
})

describe('analysis in progress', () => {
  /** A fetch that answers only when the test says so. */
  function pendingFetch() {
    let answer: (response: Response) => void = () => undefined
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => (answer = resolve)))
    vi.stubGlobal('fetch', fetchMock)
    return { fetchMock, answer: (response: Response) => answer(response) }
  }

  it('shows the real checks while a link is analysed, blocks a second submit and shows the result only on the response', async () => {
    const { fetchMock, answer } = pendingFetch()
    renderRoute('/check/url')
    await userEvent.type(screen.getByLabelText('Link'), 'http://sbi.co.in.kyc-verify.xyz/login')
    await userEvent.click(screen.getByRole('button', { name: 'Check link' }))

    const progress = await screen.findByTestId('analysis-progress')
    expect(screen.getAllByTestId('analysis-stage').map((stage) => stage.textContent)).toEqual([
      'Reading the link',
      'Looking for tricks in the web address',
      'Checking scam databases',
      'Adding up the warning signs',
    ])
    expect(progress.textContent).not.toMatch(/\d+ ?%/) // no invented percentage
    expect(screen.queryByRole('article', { name: 'Analysis result' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Check link' })).toBeDisabled() // no duplicate submit
    expect(fetchMock).toHaveBeenCalledTimes(1)

    answer(jsonResponse(maliciousUrl))
    expect(await screen.findByRole('article', { name: 'Analysis result' })).toBeInTheDocument()
    expect(screen.queryByTestId('analysis-progress')).toBeNull()
  })

  it('lists QR decoding first for an uploaded QR image', async () => {
    const { answer } = pendingFetch()
    const { container } = renderRoute('/check/qr')
    await userEvent.upload(container.querySelector('input[type=file]') as HTMLInputElement, new File(['p'], 'qr.png', { type: 'image/png' }))
    await userEvent.click(screen.getByRole('button', { name: 'Check QR code' }))
    const stages = (await screen.findAllByTestId('analysis-stage')).map((stage) => stage.textContent)
    expect(stages[0]).toBe('Reading the QR code')
    expect(stages).toContain('Checking scam databases')
    answer(jsonResponse(qrResult))
    expect(await screen.findByRole('article', { name: 'Analysis result' })).toBeInTheDocument()
  })

  it('replaces the progress with the error when the request fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('offline'))))
    renderRoute('/check/url')
    await userEvent.type(screen.getByLabelText('Link'), 'example.com')
    await userEvent.click(screen.getByRole('button', { name: 'Check link' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not complete the check')
    expect(screen.queryByTestId('analysis-progress')).toBeNull()
    expect(screen.getByRole('button', { name: 'Check link' })).toBeEnabled() // retry possible
  })
})

describe('Airlock check page', () => {
  // Reveal the stages at once (the page honours prefers-reduced-motion).
  beforeEach(() => {
    vi.stubGlobal('matchMedia', (query: string) => ({ matches: query.includes('reduce'), addEventListener() {}, removeEventListener() {} }))
  })

  function pendingAnalysis() {
    let answer: (response: Response) => void = () => undefined
    const fetchMock = vi.fn((url: RequestInfo | URL) =>
      String(url).endsWith('/api/health') ? Promise.resolve(healthyResponse()) : new Promise<Response>((resolve) => (answer = resolve)),
    )
    vi.stubGlobal('fetch', fetchMock)
    return { fetchMock, answer: (response: Response) => answer(response) }
  }
  const healthyResponse = () => jsonResponse({ status: 'ok', engine_version: '1.0.0', components: {} })
  const analyzeCalls = (fetchMock: ReturnType<typeof vi.fn>) => fetchMock.mock.calls.filter(([url]) => /\/api\/analyze\//.test(String(url)))

  it('detects a link, checks it on the server, then reveals the real steps, log and result', async () => {
    const { fetchMock, answer } = pendingAnalysis()
    renderRoute('/')
    const field = screen.getByLabelText('Paste a link, UPI ID or message')
    await userEvent.type(field, 'http://sbi.co.in.kyc-verify.xyz/login')
    expect(screen.getByTestId('detected-type')).toHaveTextContent('Looks like a link')
    await userEvent.click(screen.getByRole('button', { name: 'Check it' }))

    expect(screen.getByTestId('chamber')).toHaveAttribute('data-phase', 'running')
    expect(screen.getByTestId('chamber-status')).toHaveTextContent('Status · Checking…')
    expect(screen.getByTestId('specimen')).toHaveTextContent('http://sbi.co.in.kyc-verify.xyz/login')
    expect(screen.getAllByTestId('stage').map((s) => s.dataset.state)).toEqual(['active', 'active', 'active', 'active', 'waiting'])
    expect(screen.getByRole('button', { name: 'Check it' })).toBeDisabled() // no double submit
    const [url, init] = analyzeCalls(fetchMock)[0] ?? []
    expect(String(url)).toMatch(/\/api\/analyze\/url$/)
    expect(JSON.parse(String(init?.body)).url).toBe('http://sbi.co.in.kyc-verify.xyz/login')
    expect(screen.queryByRole('article', { name: 'Analysis result' })).toBeNull()

    answer(jsonResponse(maliciousUrl))
    expect(await screen.findByRole('article', { name: 'Analysis result' })).toBeInTheDocument()
    expect(screen.getByTestId('chamber')).toHaveAttribute('data-phase', 'done')
    expect(screen.getAllByTestId('stage').map((s) => s.dataset.state)).toEqual(['done', 'done', 'warning', 'warning', 'warning'])
    const log = screen.getByTestId('chamber-log')
    expect(log).toHaveTextContent('sent to our server · your phone does not open it')
    expect(log).toHaveTextContent('result: MALICIOUS · risk 73 out of 100')
  })

  it('sends a UPI ID as a payment payload and a message to the message check', async () => {
    const { fetchMock, answer } = pendingAnalysis()
    renderRoute('/')
    const field = screen.getByLabelText('Paste a link, UPI ID or message')
    await userEvent.type(field, 'refund.desk9912@okdemo{Enter}')
    const [qrUrl, qrInit] = analyzeCalls(fetchMock)[0] ?? []
    expect(String(qrUrl)).toMatch(/\/api\/analyze\/qr$/)
    expect(JSON.parse(String(qrInit?.body)).content).toBe('upi://pay?pa=refund.desk9912%40okdemo')
    answer(jsonResponse(qrResult))
    await screen.findByRole('article', { name: 'Analysis result' })

    await userEvent.click(screen.getByRole('button', { name: 'Check something else' }))
    expect(screen.getByTestId('chamber')).toHaveAttribute('data-phase', 'idle')
    expect(field).toHaveFocus()
    await userEvent.clear(field)
    await userEvent.type(field, 'Your KYC expires today, share the OTP{Enter}')
    const [messageUrl, messageInit] = analyzeCalls(fetchMock)[1] ?? []
    expect(String(messageUrl)).toMatch(/\/api\/analyze\/message$/)
    expect(JSON.parse(String(messageInit?.body)).text).toBe('Your KYC expires today, share the OTP')
  })

  it('uploads an image to the combined QR + text check and refuses other files in the browser', async () => {
    const { fetchMock, answer } = pendingAnalysis()
    const { container } = renderRoute('/')
    const input = container.querySelector('input[type=file]') as HTMLInputElement
    await userEvent.upload(input, new File(['%PDF'], 'doc.pdf', { type: 'application/pdf' }), { applyAccept: false })
    expect(screen.getByRole('alert')).toHaveTextContent('Please choose a PNG, JPEG or WEBP image.')
    expect(analyzeCalls(fetchMock)).toHaveLength(0)
    await userEvent.upload(input, new File(['png'], 'shot.png', { type: 'image/png' }))
    expect(String(analyzeCalls(fetchMock)[0]?.[0])).toMatch(/\/api\/analyze\/screenshot$/)
    expect(screen.getByTestId('specimen')).toHaveTextContent('shot.png')
    answer(jsonResponse(screenshotResult))
    await screen.findByRole('article', { name: 'Analysis result' })
  })

  it('a failed check stops, shows the error and never a result', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).endsWith('/api/health')) return healthyResponse()
      throw new TypeError('offline')
    }))
    renderRoute('/')
    await userEvent.type(screen.getByLabelText('Paste a link, UPI ID or message'), 'example.com{Enter}')
    expect(await screen.findByText('Could not complete the check')).toBeInTheDocument()
    expect(screen.getByTestId('chamber')).toHaveAttribute('data-phase', 'failed')
    // the log line is appended on the next tick, after the error renders
    await waitFor(() => expect(screen.getByTestId('chamber-log')).toHaveTextContent('stopped:'))
    expect(screen.queryByRole('article', { name: 'Analysis result' })).toBeNull()
  })
})
