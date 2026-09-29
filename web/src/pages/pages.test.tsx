import { screen, waitFor } from '@testing-library/react'
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
    expect(await screen.findByTestId('backend-status')).toHaveTextContent(
      'Server online · engine 0.1.0 · text recognition available · 1 threat-intelligence source active',
    )
    expect(screen.getByRole('link', { name: /Check a link/ })).toHaveAttribute('href', '/check/url')
  })

  it('warns when the backend is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('offline'))))
    renderRoute('/')
    expect(await screen.findByText(/not reachable right now/)).toBeInTheDocument()
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
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ url: 'http://sbi.co.in.kyc-verify.xyz/login' }))
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
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ text: 'Share your OTP' }))
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
    await waitFor(() => expect(screen.getByRole('link', { name: 'Safety tips' })).toHaveClass('bg-teal-700'))
  })
})
