import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native'
import { useEffect, type ReactNode } from 'react'
import { AuthProvider } from '../context/AuthContext'
import { ResultProvider, useResult } from '../context/ResultContext'
import { NoAuthClient, type AuthClient } from '../services/auth'
import { jsonResponse, maliciousUrl, qrResult } from './fixtures'
import UrlCheck from '../app/check/url'
import MessageCheck from '../app/check/message'
import CameraScan from '../app/scan/camera'
import ScreenshotCheck from '../app/check/screenshot'
import QrImageCheck from '../app/scan/image'
import Generate from '../app/generate'
import Home from '../app/(tabs)/index'
import Settings from '../app/(tabs)/settings'
import ResultScreen from '../app/result'
import * as picker from 'expo-image-picker'

const mockPush = jest.fn()
const mockReplace = jest.fn()
jest.mock('expo-router', () => ({
  useRouter: () => ({ push: mockPush, replace: mockReplace }),
  useFocusEffect: (effect: () => void) => {
    const { useEffect } = jest.requireActual<typeof import('react')>('react')
    useEffect(effect, [effect])
  },
}))

let mockScan: ((event: { data: string }) => void) | undefined
let mockPermission: { granted: boolean; canAskAgain: boolean } | null = { granted: true, canAskAgain: true }
const mockRequestPermission = jest.fn()
jest.mock('expo-camera', () => ({
  useCameraPermissions: () => [mockPermission, mockRequestPermission],
  CameraView: function MockCameraView(props: { onBarcodeScanned?: (event: { data: string }) => void }) {
    mockScan = props.onBarcodeScanned
    return null
  },
}))

jest.mock('expo-image-picker', () => ({
  launchImageLibraryAsync: jest.fn(),
}))

jest.mock('react-native-qrcode-svg', () => {
  const { Text } = jest.requireActual<typeof import('react-native')>('react-native')
  function MockQRCode({ value }: { value: string }) {
    return <Text testID="qr-value">{value}</Text>
  }
  return MockQRCode
})

const realFetch = global.fetch
let fetchMock: jest.Mock<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>
beforeEach(() => {
  mockPush.mockClear()
  mockScan = undefined
  mockPermission = { granted: true, canAskAgain: true }
  fetchMock = jest.fn(async () => jsonResponse(maliciousUrl))
  global.fetch = fetchMock as unknown as typeof fetch
})
afterEach(() => {
  global.fetch = realFetch
})

const latestResult: { current: ReturnType<typeof useResult> | null } = { current: null }
function Probe() {
  const value = useResult()
  useEffect(() => {
    latestResult.current = value
  })
  return null
}
function wrap(ui: ReactNode, client: AuthClient = new NoAuthClient()) {
  return render(
    <AuthProvider client={client}>
      <ResultProvider>
        {ui}
        <Probe />
      </ResultProvider>
    </AuthProvider>,
  )
}

describe('URL check', () => {
  it('analyses the link and opens the result screen', async () => {
    await wrap(<UrlCheck />)
    await fireEvent.changeText(screen.getByLabelText('Link'), '  http://sbi.co.in.kyc-verify.xyz/login ')
    await fireEvent.press(screen.getByText('Check link'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    expect(latestResult.current?.result?.risk_level).toBe('MALICIOUS')
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ url: 'http://sbi.co.in.kyc-verify.xyz/login', save_to_history: false }))
  })

  it('shows backend errors and stays on the screen', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse({ error: { code: 'INVALID_URL', message: 'The link has no domain name.', request_id: 'r1' } }, 400),
    )
    await wrap(<UrlCheck />)
    await fireEvent.changeText(screen.getByLabelText('Link'), 'http://')
    await fireEvent.press(screen.getByText('Check link'))
    expect(await screen.findByTestId('error-banner')).toHaveTextContent(/no domain name/)
    expect(mockPush).not.toHaveBeenCalled()
  })
})

describe('message check', () => {
  it('counts characters and sends the text', async () => {
    await wrap(<MessageCheck />)
    await fireEvent.changeText(screen.getByLabelText('Message text'), 'Share your OTP')
    expect(screen.getByText(/14 \/ 5000/)).toBeOnTheScreen()
    await fireEvent.press(screen.getByText('Check message'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(JSON.stringify({ text: 'Share your OTP', save_to_history: false }))
  })
})

describe('QR camera scan', () => {
  it('asks for camera permission first', async () => {
    mockPermission = { granted: false, canAskAgain: true }
    await wrap(<CameraScan />)
    await fireEvent.press(screen.getByText('Allow camera'))
    expect(mockRequestPermission).toHaveBeenCalled()
  })

  it('scans once, sends the content and never opens it', async () => {
    fetchMock.mockImplementation(async () => jsonResponse(qrResult))
    await wrap(<CameraScan />)
    await act(async () => {
      mockScan?.({ data: 'upi://pay?pa=refund.desk9912@okdemo' })
      mockScan?.({ data: 'upi://pay?pa=refund.desk9912@okdemo' })
    })
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[1]?.body).toBe(
      JSON.stringify({ content: 'upi://pay?pa=refund.desk9912@okdemo', source: 'camera', save_to_history: false }),
    )
  })

  it('lets the user scan again after an error', async () => {
    fetchMock.mockImplementation(async () => {
      throw new TypeError('Network request failed')
    })
    await wrap(<CameraScan />)
    await act(async () => mockScan?.({ data: 'hello' }))
    expect(await screen.findByTestId('error-banner')).toHaveTextContent(/Cannot reach/)
    await act(async () => mockScan?.({ data: 'hello' }))
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

describe('image upload screens', () => {
  it('uploads a picked screenshot', async () => {
    ;(picker.launchImageLibraryAsync as jest.Mock).mockResolvedValue({
      canceled: false,
      assets: [{ uri: 'file:///shot.png', mimeType: 'image/png', fileName: 'shot.png', fileSize: 1000 }],
    } as never)
    await wrap(<ScreenshotCheck />)
    await fireEvent.press(screen.getByText('Choose a screenshot'))
    await screen.findByLabelText('Selected image')
    await fireEvent.press(screen.getByText('Check screenshot'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/screenshot$/)
  })

  it('rejects unsupported and oversized images before uploading', async () => {
    const launch = picker.launchImageLibraryAsync as jest.Mock
    launch.mockResolvedValueOnce({ canceled: false, assets: [{ uri: 'file:///a.gif', mimeType: 'image/gif' }] } as never)
    await wrap(<QrImageCheck />)
    await fireEvent.press(screen.getByText('Choose an image'))
    expect(await screen.findByText('Please choose a PNG, JPEG or WEBP image.')).toBeOnTheScreen()
    launch.mockResolvedValueOnce({
      canceled: false,
      assets: [{ uri: 'file:///b.png', mimeType: 'image/png', fileSize: 6 * 1024 * 1024 }],
    } as never)
    await fireEvent.press(screen.getByText('Choose an image'))
    expect(await screen.findByText('The image is larger than 5 MB.')).toBeOnTheScreen()
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('QR generator', () => {
  it('creates a Wi-Fi code on the phone without contacting the server', async () => {
    await wrap(<Generate />)
    await fireEvent.press(screen.getByLabelText('Wi-Fi'))
    await fireEvent.changeText(screen.getByLabelText('Network name (SSID)'), 'Home;Net')
    await fireEvent.changeText(screen.getByLabelText('Password'), 'correct-horse')
    await fireEvent.press(screen.getByText('Create QR code'))
    expect(screen.getByTestId('qr-value')).toHaveTextContent(String.raw`WIFI:T:WPA;S:Home\;Net;P:correct-horse;;`)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('shows validation errors', async () => {
    await wrap(<Generate />)
    await fireEvent.changeText(screen.getByLabelText('Link to encode'), 'javascript:alert(1)')
    await fireEvent.press(screen.getByText('Create QR code'))
    expect(screen.getByText(/Only http:\/\/ and https:\/\//)).toBeOnTheScreen()
  })
})

describe('home, settings and result', () => {
  it('home shows backend status and navigates to checks', async () => {
    fetchMock.mockImplementation(async () =>
      jsonResponse({
        status: 'ok',
        engine_version: '0.1.0',
        components: { api: 'ok', threat_intel: { enabled: true, providers: [{ provider: 'local_feed', enabled: true, external: false }] } },
      }),
    )
    await wrap(<Home />)
    expect(await screen.findByTestId('backend-status')).toHaveTextContent(/1 threat-intelligence source active/)
    await fireEvent.press(screen.getByLabelText('Scan a QR code'))
    expect(mockPush).toHaveBeenCalledWith('/scan/camera')
  })

  it('settings shows an offline server honestly', async () => {
    fetchMock.mockImplementation(async () => {
      throw new TypeError('offline')
    })
    await wrap(<Settings />)
    expect(await screen.findByTestId('backend-status')).toHaveTextContent(/not reachable/)
  })

  it('result screen renders the stored result', async () => {
    function Seed() {
      const { setResult, result } = useResult()
      if (!result) setTimeout(() => setResult(maliciousUrl), 0)
      return null
    }
    await render(
      <ResultProvider>
        <Seed />
        <ResultScreen />
      </ResultProvider>,
    )
    expect(await screen.findByTestId('result-view')).toBeOnTheScreen()
  })

  it('result screen without a result offers a way back', async () => {
    await wrap(<ResultScreen />)
    await fireEvent.press(screen.getByText('Back to home'))
    expect(mockReplace).toHaveBeenCalledWith('/')
  })
})
