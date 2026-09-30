import { useEffect, useRef, useState } from 'react'

/**
 * Live QR scanning with the device camera. Frames are decoded in the browser (jsQR); only the
 * decoded text is passed on (it is then sent to the backend for analysis). The code is never
 * opened. Scanning stops after the first code, and the camera is released when not needed.
 */
export function QrCameraScanner({ onCode, paused }: { onCode: (content: string) => void; paused: boolean }) {
  const videoRef = useRef<HTMLVideoElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [starting, setStarting] = useState(true)

  useEffect(() => {
    if (paused) return
    let stream: MediaStream | null = null
    let frame = 0
    let stopped = false

    async function start() {
      if (!navigator.mediaDevices?.getUserMedia) {
        setProblem('This browser cannot use the camera here. Upload an image of the QR code instead.')
        setStarting(false)
        return
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false })
      } catch {
        setProblem('Camera access was denied or no camera is available. Upload an image of the QR code instead.')
        setStarting(false)
        return
      }
      const { default: jsQR } = await import('jsqr') // loaded only when the camera is used
      if (stopped) {
        stream.getTracks().forEach((track) => track.stop())
        return
      }
      const video = videoRef.current
      if (!video) return
      video.srcObject = stream
      await video.play().catch(() => undefined)
      setStarting(false)
      const tick = () => {
        if (stopped) return
        const canvas = canvasRef.current
        if (canvas && video.readyState >= video.HAVE_CURRENT_DATA && video.videoWidth > 0) {
          const scale = Math.min(1, 800 / Math.max(video.videoWidth, video.videoHeight))
          canvas.width = Math.round(video.videoWidth * scale)
          canvas.height = Math.round(video.videoHeight * scale)
          const context = canvas.getContext('2d', { willReadFrequently: true })
          if (context) {
            context.drawImage(video, 0, 0, canvas.width, canvas.height)
            const image = context.getImageData(0, 0, canvas.width, canvas.height)
            const code = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' })
            if (code?.data) {
              stopped = true
              onCode(code.data.slice(0, 4096))
              return
            }
          }
        }
        frame = requestAnimationFrame(tick)
      }
      frame = requestAnimationFrame(tick)
    }

    void start()
    return () => {
      stopped = true
      cancelAnimationFrame(frame)
      stream?.getTracks().forEach((track) => track.stop())
    }
  }, [paused, onCode])

  if (problem) {
    return (
      <p role="alert" className="text-sm text-amber-800 dark:text-amber-300">
        {problem}
      </p>
    )
  }
  return (
    <div className="space-y-2">
      <div className="relative mx-auto aspect-square w-full max-w-sm overflow-hidden rounded-xl bg-black">
        <video ref={videoRef} className="h-full w-full object-cover" muted playsInline aria-label="Camera preview" />
        <div className="pointer-events-none absolute inset-8 rounded-xl border-4 border-white/80" aria-hidden="true" />
      </div>
      <canvas ref={canvasRef} className="hidden" />
      <p className="text-center text-sm text-slate-600 dark:text-slate-300" role="status">
        {paused ? 'QR code found – checking…' : starting ? 'Starting the camera…' : 'Point the camera at a QR code.'}
      </p>
    </div>
  )
}
