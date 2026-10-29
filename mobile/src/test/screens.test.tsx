import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native'
import { useEffect, type ReactNode } from 'react'
import { AuthProvider } from '../context/AuthContext'
import { ResultProvider, useResult } from '../context/ResultContext'
import { NoAuthClient, type AuthClient } from '../services/auth'
import { jsonResponse, maliciousUrl, qrResult } from './fixtures'
import UrlCheck from '../app/check/url'
import MessageCheck from '../app/check/message'
import CameraScan, { cameraAccess } from '../app/scan/camera'
import ImageCheck from '../app/check/image'
import Generate from '../app/generate'
import Home from '../app/(tabs)/index'
import Settings from '../app/(tabs)/settings'
import ResultScreen from '../app/result'
import * as picker from 'expo-image-picker'
import { AppState } from 'react-native'
import { openAppSettings } from '../utils/systemSettings'

const mockPush = jest.fn()
const mockReplace = jest.fn()
jest.mock('expo-router', () => ({
  useRouter: () => ({ push: mockPush, replace: mockReplace }),
  useFocusEffect: (effect: () => void) => {
    const { useEffect } = jest.requireActual<typeof import('react')>('react')
    useEffect(effect, [effect])
  },
}))

type Permission = { granted: boolean; canAskAgain: boolean; status: string }
let mockScan: ((event: { data: string }) => void) | undefined
let mockMountError: (() => void) | undefined
let mockPermission: Permission | null = { granted: true, canAskAgain: true, status: 'granted' }
const mockRequestPermission = jest.fn()
const mockGetPermission = jest.fn()
jest.mock('expo-camera', () => ({
  useCameraPermissions: () => [mockPermission, mockRequestPermission, mockGetPermission],
  CameraView: function MockCameraView(props: { onBarcodeScanned?: (event: { data: string }) => void; onMountError?: () => void }) {
    mockScan = props.onBarcodeScanned
    mockMountError = props.onMountError
    return null
  },
}))

jest.mock('../utils/systemSettings', () => ({ openAppSettings: jest.fn(async () => true) }))

const mockSaveAsync = jest.fn(async () => ({ uri: 'file:///prepared.jpg', width: 900, height: 2000 }))
const mockResize = jest.fn()
jest.mock('expo-image-manipulator', () => ({
  SaveFormat: { JPEG: 'jpeg' },
  ImageManipulator: {
    manipulate: () => ({ resize: mockResize, renderAsync: async () => ({ saveAsync: mockSaveAsync }) }),
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

let appStateListeners: ((state: string) => void)[] = []
const realFetch = global.fetch
let fetchMock: jest.Mock<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>
beforeEach(() => {
  mockPush.mockClear()
  mockScan = undefined
  mockPermission = { granted: true, canAskAgain: true, status: 'granted' }
  mockRequestPermission.mockClear()
  mockGetPermission.mockClear()
  mockReplace.mockClear()
  mockResize.mockClear()
  appStateListeners = []
  jest.spyOn(AppState, 'addEventListener').mockImplementation(((_type: string, listener: (state: string) => void) => {
    appStateListeners.push(listener)
    return { remove: () => undefined }
  }) as never)
  fetchMock = jest.fn(async () => jsonResponse(maliciousUrl))
  global.fetch = fetchMock as unknown as typeof fetch
})
afterEach(() => {
  global.fetch = realFetch
  jest.restoreAllMocks()
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
  it('maps every permission state to the right screen', () => {
    expect(cameraAccess(null)).toBe('loading')
    expect(cameraAccess({ granted: true, canAskAgain: true, status: 'granted' })).toBe('granted')
    expect(cameraAccess({ granted: false, canAskAgain: true, status: 'undetermined' })).toBe('ask')
    expect(cameraAccess({ granted: false, canAskAgain: true, status: 'denied' })).toBe('ask-again')
    expect(cameraAccess({ granted: false, canAskAgain: false, status: 'denied' })).toBe('blocked')
  })

  it('explains and asks for camera permission first', async () => {
    mockPermission = { granted: false, canAskAgain: true, status: 'undetermined' }
    await wrap(<CameraScan />)
    expect(screen.getByText(/uses the camera only to scan QR codes/)).toBeOnTheScreen()
    await fireEvent.press(screen.getByText('Allow camera'))
    expect(mockRequestPermission).toHaveBeenCalled()
  })

  it('asks again after a denial and explains why', async () => {
    mockPermission = { granted: false, canAskAgain: true, status: 'denied' }
    await wrap(<CameraScan />)
    expect(screen.getByTestId('camera-denied')).toBeOnTheScreen()
    await fireEvent.press(screen.getByText('Allow camera'))
    expect(mockRequestPermission).toHaveBeenCalled()
  })

  it('sends a permanent denial to the system settings instead of asking uselessly', async () => {
    mockPermission = { granted: false, canAskAgain: false, status: 'denied' }
    await wrap(<CameraScan />)
    expect(screen.getByTestId('camera-blocked')).toBeOnTheScreen()
    expect(screen.queryByText('Allow camera')).toBeNull()
    await fireEvent.press(screen.getByText('Open settings'))
    expect(openAppSettings).toHaveBeenCalled()
    mockGetPermission.mockClear()
    await fireEvent.press(screen.getByText('I allowed it – check again'))
    expect(mockGetPermission).toHaveBeenCalled()
  })

  it('re-reads the permission when the user returns from the settings', async () => {
    mockPermission = { granted: false, canAskAgain: false, status: 'denied' }
    await wrap(<CameraScan />)
    mockGetPermission.mockClear()
    await act(async () => appStateListeners.forEach((listener) => listener('active')))
    expect(mockGetPermission).toHaveBeenCalled()
  })

  it('offers checking an image or typing the link instead', async () => {
    mockPermission = { granted: false, canAskAgain: false, status: 'denied' }
    await wrap(<CameraScan />)
    await fireEvent.press(screen.getByText('Choose an image instead'))
    expect(mockReplace).toHaveBeenCalledWith('/check/image')
    await fireEvent.press(screen.getByText('Type or paste the link'))
    expect(mockReplace).toHaveBeenCalledWith('/check/url')
  })

  it('recovers when the camera cannot start', async () => {
    await wrap(<CameraScan />)
    await act(async () => mockMountError?.())
    expect(screen.getByTestId('camera-error')).toBeOnTheScreen()
    await fireEvent.press(screen.getByText('Try again'))
    expect(screen.queryByTestId('camera-error')).toBeNull()
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

describe('choose image to check (screenshots and QR photos)', () => {
  const pick = picker.launchImageLibraryAsync as jest.Mock

  it('prepares the picked image and uploads it to the combined QR + text check', async () => {
    pick.mockResolvedValue({
      canceled: false,
      assets: [{ uri: 'file:///shot.png', mimeType: 'image/png', fileName: 'shot.png', fileSize: 1000, width: 1440, height: 3200 }],
    } as never)
    const append = jest.spyOn(FormData.prototype, 'append')
    await wrap(<ImageCheck />)
    await fireEvent.press(screen.getByText('Choose image to check'))
    await screen.findByLabelText('Selected image')
    expect(mockResize).toHaveBeenCalledWith({ height: 1600 })
    await fireEvent.press(screen.getByText('Check image'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
    expect(String(fetchMock.mock.calls[0]?.[0])).toMatch(/\/api\/analyze\/screenshot$/)
    const file = append.mock.calls.find(([name]) => name === 'file')?.[1]
    expect(file).toMatchObject({ uri: 'file:///prepared.jpg', type: 'image/jpeg' })
    append.mockRestore()
  })

  it('rejects unsupported images and unpreparable oversized images before uploading', async () => {
    pick.mockResolvedValueOnce({ canceled: false, assets: [{ uri: 'file:///a.gif', mimeType: 'image/gif', width: 10, height: 10 }] } as never)
    await wrap(<ImageCheck />)
    await fireEvent.press(screen.getByText('Choose image to check'))
    expect(await screen.findByText('Please choose a photo or screenshot (PNG, JPEG, WEBP or HEIC).')).toBeOnTheScreen()
    mockSaveAsync.mockRejectedValueOnce(new Error('decode failed') as never)
    pick.mockResolvedValueOnce({
      canceled: false,
      assets: [{ uri: 'file:///b.png', mimeType: 'image/png', fileSize: 6 * 1024 * 1024, width: 4000, height: 9000 }],
    } as never)
    await fireEvent.press(screen.getByText('Choose image to check'))
    expect(await screen.findByText(/could not be prepared for checking/)).toBeOnTheScreen()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('explains an interrupted upload and lets the user retry it', async () => {
    pick.mockResolvedValue({
      canceled: false,
      assets: [{ uri: 'file:///shot.png', mimeType: 'image/png', width: 1080, height: 2400 }],
    } as never)
    fetchMock.mockImplementation(async (input) => {
      if (String(input).endsWith('/api/health')) return jsonResponse({ status: 'ok', engine_version: '1', components: { api: 'ok' } })
      throw new TypeError('Network request failed')
    })
    await wrap(<ImageCheck />)
    await fireEvent.press(screen.getByText('Choose image to check'))
    await screen.findByLabelText('Selected image')
    await fireEvent.press(screen.getByText('Check image'))
    // shown after the automatic retry (UPLOAD_RETRY_DELAY_MS) also failed
    expect(await screen.findByTestId('error-banner', {}, { timeout: 5000 })).toHaveTextContent(/image upload was interrupted/)
    expect(fetchMock.mock.calls.filter(([url]) => String(url).endsWith('/api/analyze/screenshot'))).toHaveLength(2)
    fetchMock.mockImplementation(async () => jsonResponse(qrResult))
    await fireEvent.press(screen.getByText('Try again'))
    await waitFor(() => expect(mockPush).toHaveBeenCalledWith('/result'))
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
