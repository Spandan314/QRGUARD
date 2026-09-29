import { render, screen, waitFor } from '@testing-library/react'
import { QrCameraScanner } from './QrCameraScanner'

vi.mock('jsqr', () => ({ default: vi.fn(() => ({ data: 'upi://pay?pa=refund.desk9912@okdemo' })) }))

function fakeCamera() {
  const stop = vi.fn()
  const stream = { getTracks: () => [{ stop }] } as unknown as MediaStream
  const getUserMedia = vi.fn(async () => stream)
  Object.defineProperty(navigator, 'mediaDevices', { value: { getUserMedia }, configurable: true })
  vi.spyOn(HTMLMediaElement.prototype, 'play').mockResolvedValue(undefined)
  Object.defineProperty(HTMLVideoElement.prototype, 'readyState', { get: () => 4, configurable: true })
  Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', { get: () => 640, configurable: true })
  Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', { get: () => 480, configurable: true })
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue({
    drawImage: vi.fn(),
    getImageData: () => ({ data: new Uint8ClampedArray(4), width: 1, height: 1 }),
  } as unknown as CanvasRenderingContext2D)
  return { getUserMedia, stop }
}

afterEach(() => {
  Object.defineProperty(navigator, 'mediaDevices', { value: undefined, configurable: true })
})

describe('QrCameraScanner', () => {
  it('decodes a code from the camera once, asks only for video and releases the camera', async () => {
    const { getUserMedia, stop } = fakeCamera()
    const onCode = vi.fn()
    const { unmount } = render(<QrCameraScanner onCode={onCode} paused={false} />)
    await waitFor(() => expect(onCode).toHaveBeenCalledWith('upi://pay?pa=refund.desk9912@okdemo'))
    expect(onCode).toHaveBeenCalledTimes(1)
    expect(getUserMedia).toHaveBeenCalledWith({ video: { facingMode: 'environment' }, audio: false })
    unmount()
    expect(stop).toHaveBeenCalled()
  })

  it('explains when camera access is denied', async () => {
    Object.defineProperty(navigator, 'mediaDevices', {
      value: { getUserMedia: vi.fn(async () => Promise.reject(new DOMException('denied', 'NotAllowedError'))) },
      configurable: true,
    })
    render(<QrCameraScanner onCode={vi.fn()} paused={false} />)
    expect(await screen.findByRole('alert')).toHaveTextContent(/denied or no camera/)
  })

  it('does not start the camera while paused', () => {
    const { getUserMedia } = fakeCamera()
    render(<QrCameraScanner onCode={vi.fn()} paused />)
    expect(getUserMedia).not.toHaveBeenCalled()
    expect(screen.getByRole('status')).toHaveTextContent('QR code found')
  })
})
