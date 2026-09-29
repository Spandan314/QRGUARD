import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DevAuthClient, NoAuthClient } from '../services/auth'
import { jsonResponse, maliciousUrl } from '../test/fixtures'
import { renderRoute } from '../test/renderRoute'
import type { HistoryItem, Profile } from '../types/api'

type Handler = (url: string, init: RequestInit) => Response | Promise<Response>

function stubBackend(routes: Record<string, Handler>) {
  const calls: { url: string; init: RequestInit }[] = []
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const request = init ?? {}
    calls.push({ url, init: request })
    const key = Object.keys(routes).find((pattern) => new RegExp(pattern).test(`${request.method ?? 'GET'} ${url}`))
    const handler = key ? routes[key] : undefined
    return handler ? handler(url, request) : jsonResponse({ status: 'ok', engine_version: '0.1.0', components: { api: 'ok' } })
  })
  vi.stubGlobal('fetch', fetchMock)
  return calls
}

const profile = (overrides: Partial<Profile> = {}): Profile => ({
  uid: 'dev-alice',
  is_anonymous: false,
  admin: false,
  save_history: true,
  history_retention_days: 90,
  ...overrides,
})

const item = (id: string, overrides: Partial<HistoryItem> = {}): HistoryItem => ({
  id,
  input_type: 'url',
  created_at: '2026-09-29T10:00:00+00:00',
  risk_score: 70,
  risk_level: 'MALICIOUS',
  confidence: 'HIGH',
  verification: { status: 'UNVERIFIED', source: null },
  categories: ['phishing'],
  indicators: [{ id: 'BRAND_LOOKALIKE', title: 'Look-alike of a brand', severity: 'critical', score_contribution: 60, source: 'link' }],
  recommended_action: 'Do not open this link.',
  target: { kind: 'url', domain: 'flipkrat.com', url_hash: 'a'.repeat(64) },
  threat_intel: [],
  engine_version: '0.1.0',
  ...overrides,
})

function callTo(calls: { url: string; init: RequestInit }[], suffix: string) {
  const call = calls.find((c) => c.url.endsWith(suffix))
  if (!call) throw new Error(`no call to ${suffix}`)
  return call
}

function first<T>(items: T[]): T {
  const [item] = items
  if (item === undefined) throw new Error('empty list')
  return item
}

function authHeader(init: RequestInit): string | null {
  return new Headers(init.headers).get('Authorization')
}

beforeEach(() => {
  sessionStorage.clear()
})

describe('sign-in (demo mode)', () => {
  it('signs in, shows history in the navigation and signs out', async () => {
    stubBackend({ 'GET .*/api/me$': () => jsonResponse(profile()) })
    renderRoute('/account', new DevAuthClient())
    expect(screen.queryByRole('link', { name: 'History' })).toBeNull()
    await userEvent.type(screen.getByLabelText('Demo user name'), 'alice')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByText('Signed in')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'History' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Account' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Sign out' }))
    expect(await screen.findByLabelText('Demo user name')).toBeInTheDocument()
  })

  it('rejects too-short demo names', async () => {
    stubBackend({})
    renderRoute('/account', new DevAuthClient())
    await userEvent.type(screen.getByLabelText('Demo user name'), 'ab')
    expect(screen.getByRole('button', { name: 'Sign in' })).toBeDisabled()
  })

  it('explains when sign-in is not configured', () => {
    stubBackend({})
    renderRoute('/account', new NoAuthClient())
    expect(screen.getByText(/Sign-in is not configured/)).toBeInTheDocument()
  })
})

describe('signed-in checks', () => {
  it('sends the token and the save choice, and shows that the result was saved', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    const calls = stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'POST .*/api/analyze/url$': () => jsonResponse({ ...maliciousUrl, history: { saved: true, scan_id: 'scan1234567' } }),
      'POST .*/api/reports$': () => jsonResponse({ id: 'report123456' }, 201),
    })
    renderRoute('/check/url', new DevAuthClient())
    const save = await screen.findByLabelText(/Save the result to my history/)
    expect(save).toBeChecked()
    await userEvent.type(screen.getByLabelText('Link'), 'http://sbi.co.in.kyc-verify.xyz/login')
    await userEvent.click(screen.getByRole('button', { name: 'Check link' }))
    expect(await screen.findByTestId('history-notice')).toHaveTextContent('Saved to your history')
    const analyze = callTo(calls, '/api/analyze/url')
    expect(authHeader(analyze.init)).toBe('Bearer dev-alice')
    expect(JSON.parse(String(analyze.init.body))).toEqual({ url: 'http://sbi.co.in.kyc-verify.xyz/login', save_to_history: true })

    // report the result
    await userEvent.click(screen.getByRole('button', { name: /Report it/ }))
    await userEvent.click(screen.getByLabelText('It is genuine (wrongly flagged)'))
    await userEvent.type(screen.getByLabelText(/Note/), 'This is my bank')
    await userEvent.click(screen.getByRole('button', { name: 'Send report' }))
    expect(await screen.findByText(/your report was sent/)).toBeInTheDocument()
    const report = callTo(calls, '/api/reports')
    expect(JSON.parse(String(report.init.body))).toEqual({
      reported_as: 'false_positive',
      note: 'This is my bank',
      scan_id: 'scan1234567',
    })
  })

  it('does not save when the user unticks the box', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    const calls = stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'POST .*/api/analyze/message$': () => jsonResponse(maliciousUrl),
    })
    renderRoute('/check/message', new DevAuthClient())
    await userEvent.click(await screen.findByLabelText(/Save the result to my history/))
    await userEvent.type(screen.getByLabelText('Message text'), 'hello there')
    await userEvent.click(screen.getByRole('button', { name: 'Check message' }))
    await screen.findByRole('article', { name: 'Analysis result' })
    const body = JSON.parse(String(callTo(calls, '/api/analyze/message').init.body))
    expect(body.save_to_history).toBe(false)
  })

  it('invites signed-out users to sign in instead of offering to save', async () => {
    stubBackend({})
    renderRoute('/check/url', new DevAuthClient())
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Sign in' })).toBeInTheDocument()
    expect(screen.queryByLabelText(/Save the result/)).toBeNull()
  })
})

describe('history page', () => {
  it('lists, expands, pages and deletes saved results', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    const calls = stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'GET .*/api/history\\?limit=20&cursor=cursor123': () =>
        jsonResponse({ items: [item('third12345', { input_type: 'message', target: { kind: 'message', length: 120, url_count: 1 } })], next_cursor: null }),
      'GET .*/api/history\\?limit=20$': () =>
        jsonResponse({ items: [item('first12345'), item('second1234', { input_type: 'qr_camera', target: { kind: 'upi', payee_domain: '@okdemo' } })], next_cursor: 'cursor123' }),
      'DELETE .*/api/history/first12345$': () => new Response(null, { status: 204 }),
      'DELETE .*/api/history$': () => jsonResponse({ deleted: 2 }),
    })
    renderRoute('/history', new DevAuthClient())
    const rows = await screen.findAllByTestId('history-item')
    expect(rows).toHaveLength(2)
    expect(rows[0]).toHaveTextContent('Link · flipkrat.com')
    expect(rows[1]).toHaveTextContent('UPI payment (@okdemo)')
    await userEvent.click(within(first(rows)).getByRole('button', { name: 'Details' }))
    expect(rows[0]).toHaveTextContent('Look-alike of a brand (+60)')

    await userEvent.click(screen.getByRole('button', { name: 'Load more' }))
    expect(await screen.findByText(/120 characters, 1 link$/)).toBeInTheDocument()

    await userEvent.click(within(first(screen.getAllByTestId('history-item'))).getByRole('button', { name: 'Delete this result' }))
    await waitFor(() => expect(screen.getAllByTestId('history-item')).toHaveLength(2))
    expect(calls.some((c) => c.init.method === 'DELETE' && c.url.endsWith('/first12345'))).toBe(true)

    await userEvent.click(screen.getByRole('button', { name: 'Delete all' }))
    await userEvent.click(within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Delete all' }))
    expect(await screen.findByText('No saved results yet.')).toBeInTheDocument()
  })

  it('asks signed-out users to sign in', () => {
    stubBackend({})
    renderRoute('/history', new DevAuthClient())
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Sign in' })).toHaveAttribute('href', '/account')
  })

  it('shows API errors (e.g. history unavailable)', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'GET .*/api/history': () =>
        jsonResponse({ error: { code: 'SERVICE_UNAVAILABLE', message: 'History is not available on this server.' } }, 503),
    })
    renderRoute('/history', new DevAuthClient())
    expect(await screen.findByRole('alert')).toHaveTextContent('History is not available')
  })
})

describe('account privacy controls', () => {
  it('switches saving off and deletes all data after confirmation', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    let current = profile()
    const calls = stubBackend({
      'GET .*/api/me$': () => jsonResponse(current),
      'PATCH .*/api/me$': (_url, init) => {
        current = { ...current, save_history: JSON.parse(String(init.body)).save_history }
        return jsonResponse(current)
      },
      'DELETE .*/api/me$': () => jsonResponse({ deleted_scans: 3, anonymised_reports: 1, account_deleted: false }),
    })
    renderRoute('/account', new DevAuthClient())
    const toggle = await screen.findByLabelText('Offer to save my results to my history')
    await userEvent.click(toggle)
    await waitFor(() => expect(screen.getByLabelText('Offer to save my results to my history')).not.toBeChecked())
    await userEvent.click(screen.getByRole('button', { name: 'Delete my data' }))
    await userEvent.click(screen.getByRole('button', { name: 'Yes, delete everything' }))
    expect(await screen.findByLabelText('Demo user name')).toBeInTheDocument() // signed out afterwards
    expect(calls.some((c) => c.init.method === 'DELETE' && c.url.endsWith('/api/me'))).toBe(true)
  })
})

describe('admin', () => {
  it('is hidden and refused for normal users', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-alice')
    stubBackend({ 'GET .*/api/me$': () => jsonResponse(profile()) })
    renderRoute('/admin', new DevAuthClient())
    expect(await screen.findByText('Administrator access is required.')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Admin' })).toBeNull()
  })

  it('shows stats and lets admins review reports', async () => {
    sessionStorage.setItem('qrguard.devToken', 'dev-admin-root')
    const calls = stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile({ uid: 'dev-root', admin: true })),
      'GET .*/api/admin/stats': () =>
        jsonResponse({
          days: [{ date: '2026-09-29', total: 5, by_level: { SAFE: 3, MALICIOUS: 2 }, by_type: { url: 5 }, ti_unavailable: 1 }],
          threat_intel: [{ provider: 'local_feed', enabled: true, external: false }],
        }),
      'GET .*/api/admin/reports': () =>
        jsonResponse({
          items: [
            { id: 'rep1234567', scan_id: null, reported_as: 'false_positive', domain: 'sbi.co.in', url_hash: null, note: 'Real bank', status: 'open', created_at: '2026-09-29T10:00:00+00:00' },
          ],
        }),
      'PATCH .*/api/admin/reports/rep1234567$': () => jsonResponse({ id: 'rep1234567', status: 'reviewed' }),
    })
    renderRoute('/admin', new DevAuthClient())
    await screen.findByText(/Local blocklist: enabled/)
    expect(screen.getByTestId('stat-Checks')).toHaveTextContent('5')
    expect(screen.getByTestId('stat-⛔ Malicious')).toHaveTextContent('2')
    expect(screen.getByText(/Local blocklist: enabled/)).toBeInTheDocument()
    expect(screen.getByTestId('admin-report')).toHaveTextContent('False positive · sbi.co.in')
    await userEvent.click(screen.getByRole('button', { name: 'Mark as reviewed' }))
    await waitFor(() => expect(screen.queryByTestId('admin-report')).toBeNull())
    expect(calls.some((c) => c.init.method === 'PATCH')).toBe(true)
    expect(screen.getByRole('link', { name: 'Admin' })).toBeInTheDocument()
  })
})

describe('QR camera', () => {
  it('falls back to image upload when the camera is not available', async () => {
    stubBackend({})
    renderRoute('/check/qr')
    await userEvent.click(screen.getByRole('tab', { name: 'Use the camera' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/cannot use the camera|denied/)
  })
})
