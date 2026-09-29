import { beforeEach, describe, expect, it, jest } from '@jest/globals'
import AsyncStorage from '@react-native-async-storage/async-storage'
import { fireEvent, render, screen, waitFor } from '@testing-library/react-native'
import type { ReactNode } from 'react'
import { Alert } from 'react-native'
import HistoryScreen from '../app/(tabs)/history'
import Settings from '../app/(tabs)/settings'
import UrlCheck from '../app/check/url'
import ResultScreen from '../app/result'
import { AuthProvider } from '../context/AuthContext'
import { ResultProvider } from '../context/ResultContext'
import { authErrorMessage, DevAuthClient, NoAuthClient, type AuthClient } from '../services/auth'
import type { HistoryItem, Profile } from '../types/api'
import { jsonResponse, maliciousUrl } from './fixtures'

const mockPush = jest.fn()
jest.mock('expo-router', () => ({
  useRouter: () => ({ push: mockPush, replace: jest.fn() }),
  useFocusEffect: (effect: () => void) => {
    const { useEffect } = jest.requireActual<typeof import('react')>('react')
    useEffect(effect, [effect])
  },
}))

type Handler = (url: string, init: RequestInit) => Response
let calls: { url: string; init: RequestInit }[] = []

function stubBackend(routes: Record<string, Handler>) {
  calls = []
  global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const request = init ?? {}
    calls.push({ url, init: request })
    const key = Object.keys(routes).find((pattern) => new RegExp(pattern).test(`${request.method ?? 'GET'} ${url}`))
    const handler = key ? routes[key] : undefined
    return handler ? handler(url, request) : jsonResponse({ status: 'ok', engine_version: '0.1.0', components: { api: 'ok' } })
  }) as unknown as typeof fetch
}

function callTo(suffix: string) {
  const call = calls.find((c) => c.url.endsWith(suffix))
  if (!call) throw new Error(`no call to ${suffix}`)
  return call
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

async function signedInClient() {
  const client = new DevAuthClient()
  await client.signInDemo('alice', false)
  return client
}

function wrap(ui: ReactNode, client: AuthClient) {
  return render(
    <AuthProvider client={client}>
      <ResultProvider>{ui}</ResultProvider>
    </AuthProvider>,
  )
}

beforeEach(async () => {
  mockPush.mockClear()
  jest.restoreAllMocks()
  await AsyncStorage.clear()
})

describe('account tab', () => {
  it('demo sign-in shows the account and privacy controls', async () => {
    stubBackend({ 'GET .*/api/me$': () => jsonResponse(profile()) })
    await wrap(<Settings />, new DevAuthClient())
    await fireEvent.changeText(await screen.findByLabelText('Demo user name'), 'alice')
    await fireEvent.press(screen.getByText('Sign in'))
    expect(await screen.findByText('Signed in')).toBeOnTheScreen()
    expect(await screen.findByLabelText('Offer to save my results to my history')).toBeOnTheScreen()
    expect(authHeader(callTo('/api/me'))).toBe('Bearer dev-alice')
  })

  it('switches saving off and deletes all data after confirmation', async () => {
    let current = profile()
    stubBackend({
      'GET .*/api/me$': () => jsonResponse(current),
      'PATCH .*/api/me$': (_url, init) => {
        current = { ...current, save_history: JSON.parse(String(init.body)).save_history }
        return jsonResponse(current)
      },
      'DELETE .*/api/me$': () => jsonResponse({ deleted_scans: 2, anonymised_reports: 0, account_deleted: false }),
    })
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    await wrap(<Settings />, await signedInClient())
    const toggle = await screen.findByLabelText('Offer to save my results to my history')
    await fireEvent(toggle, 'valueChange', false)
    await waitFor(() => expect(JSON.parse(String(callTo('/api/me').init.body ?? '{}'))).toBeDefined())
    expect(calls.some((c) => c.init.method === 'PATCH')).toBe(true)

    await fireEvent.press(screen.getByText('Delete my data'))
    const buttons = alert.mock.calls[0]?.[2] ?? []
    buttons.find((b) => b.text === 'Delete everything')?.onPress?.()
    expect(await screen.findByLabelText('Demo user name')).toBeOnTheScreen() // signed out
    expect(calls.some((c) => c.init.method === 'DELETE' && c.url.endsWith('/api/me'))).toBe(true)
  })

  it('explains when sign-in is not configured', async () => {
    stubBackend({})
    await wrap(<Settings />, new NoAuthClient())
    expect(screen.getByText(/Sign-in is not configured/)).toBeOnTheScreen()
  })
})

function authHeader(call: { init: RequestInit }): string | undefined {
  return (call.init.headers as Record<string, string> | undefined)?.Authorization
}

describe('signed-in checks', () => {
  it('sends the token and save choice, then shows the saved notice and lets the user report', async () => {
    stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'POST .*/api/analyze/url$': () => jsonResponse({ ...maliciousUrl, history: { saved: true, scan_id: 'scan1234567' } }),
      'POST .*/api/reports$': () => jsonResponse({ id: 'rep1234567' }, 201),
    })
    const client = await signedInClient()
    await wrap(
      <>
        <UrlCheck />
        <ResultScreen />
      </>,
      client,
    )
    expect(await screen.findByLabelText('Save the result to my history')).toHaveProp('value', true)
    await fireEvent.changeText(screen.getByLabelText('Link'), 'http://sbi.co.in.kyc-verify.xyz/login')
    await fireEvent.press(screen.getByText('Check link'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    const analyze = callTo('/api/analyze/url')
    expect(authHeader(analyze)).toBe('Bearer dev-alice')
    expect(JSON.parse(String(analyze.init.body))).toEqual({ url: 'http://sbi.co.in.kyc-verify.xyz/login', save_to_history: true })
    expect(await screen.findByTestId('history-notice')).toHaveTextContent(/Saved to your history/)

    await fireEvent.press(screen.getByText('Is this result wrong? Report it'))
    await fireEvent.press(screen.getByLabelText('It is genuine (wrongly flagged)'))
    await fireEvent.changeText(screen.getByLabelText('Note (optional)'), 'My bank')
    await fireEvent.press(screen.getByText('Send report'))
    expect(await screen.findByText(/your report was sent/)).toBeOnTheScreen()
    expect(JSON.parse(String(callTo('/api/reports').init.body))).toEqual({
      reported_as: 'false_positive',
      note: 'My bank',
      scan_id: 'scan1234567',
    })
  })

  it('invites signed-out users to sign in', async () => {
    stubBackend({})
    await wrap(<UrlCheck />, new DevAuthClient())
    await fireEvent.press(await screen.findByText(/to keep a private history/))
    expect(mockPush).toHaveBeenCalledWith('/settings')
  })
})

describe('history tab', () => {
  it('lists, expands, pages and deletes results', async () => {
    stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'GET .*/api/history\\?limit=20&cursor=cursor123': () =>
        jsonResponse({ items: [item('third12345', { input_type: 'message', target: { kind: 'message', length: 120, url_count: 1 } })], next_cursor: null }),
      'GET .*/api/history\\?limit=20$': () =>
        jsonResponse({
          items: [item('first12345'), item('second1234', { input_type: 'qr_camera', target: { kind: 'upi', payee_domain: '@okdemo' } })],
          next_cursor: 'cursor123',
        }),
      'DELETE .*/api/history/first12345$': () => new Response(null, { status: 204 }),
      'DELETE .*/api/history$': () => jsonResponse({ deleted: 2 }),
    })
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    await wrap(<HistoryScreen />, await signedInClient())
    expect(await screen.findByText('Link · flipkrat.com')).toBeOnTheScreen()
    expect(screen.getByText('QR (camera) · UPI payment (@okdemo)')).toBeOnTheScreen()
    await fireEvent.press(screen.getAllByTestId('history-item')[0] as never)
    expect(await screen.findByText('• Look-alike of a brand')).toBeOnTheScreen()
    await fireEvent.press(screen.getByText('Load more'))
    expect(await screen.findByText('Message · 120 characters, 1 link')).toBeOnTheScreen()
    await fireEvent.press(screen.getAllByText('Delete')[0] as never)
    await waitFor(() => expect(screen.queryByText('Link · flipkrat.com')).toBeNull())
    await fireEvent.press(screen.getByText('Delete all'))
    alert.mock.calls[0]?.[2]?.find((b) => b.text === 'Delete all')?.onPress?.()
    expect(await screen.findByText('No saved results yet.')).toBeOnTheScreen()
  })

  it('asks signed-out users to sign in', async () => {
    stubBackend({})
    await wrap(<HistoryScreen />, new DevAuthClient())
    await fireEvent.press(await screen.findByText('Sign in'))
    expect(mockPush).toHaveBeenCalledWith('/settings')
  })

  it('shows server errors', async () => {
    stubBackend({
      'GET .*/api/me$': () => jsonResponse(profile()),
      'GET .*/api/history': () => jsonResponse({ error: { code: 'SERVICE_UNAVAILABLE', message: 'History is not available on this server.' } }, 503),
    })
    await wrap(<HistoryScreen />, await signedInClient())
    expect(await screen.findByTestId('error-banner')).toHaveTextContent(/History is not available/)
  })
})

describe('auth services', () => {
  it('DevAuthClient keeps the session in AsyncStorage across restarts', async () => {
    const first = new DevAuthClient()
    await first.signInDemo(' Alice!! ', true)
    expect(await first.getToken()).toBe('dev-admin-alice')
    const restarted = new DevAuthClient()
    expect(await restarted.getToken()).toBe('dev-admin-alice')
    await restarted.signOut()
    expect(await new DevAuthClient().getToken()).toBeNull()
    await expect(first.signInDemo('a', false)).rejects.toThrow(/at least 3/)
  })

  it('maps sign-in errors to plain language', () => {
    expect(authErrorMessage({ code: 'auth/invalid-credential' })).toBe('Wrong e-mail or password.')
    expect(authErrorMessage({ code: 'auth/unknown', message: 'internal' })).toBe('Sign-in failed. Please try again.')
    expect(authErrorMessage(new Error('Use at least 3 letters or digits.'))).toBe('Use at least 3 letters or digits.')
  })
})
