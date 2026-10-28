import { useId, useRef, useState, type FormEvent } from 'react'
import { ACCEPTED_IMAGE_TYPES, MAX_UPLOAD_BYTES } from '../../services/api'
import { detectInput, SPECIMEN_LABEL } from '../../utils/airlock'
import { formatBytes } from '../../utils/format'
import { Icon } from '../Icon'

export const primaryButton =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-btn bg-accent px-5 text-sm font-semibold text-on-accent hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-50'
export const secondaryButton =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-btn border border-line bg-panel px-4 text-sm font-medium text-ink hover:bg-panel-2 disabled:cursor-not-allowed disabled:opacity-50'

/**
 * One field for a link, a UPI ID or a message (detected automatically), plus the camera and an
 * image upload. Images are checked in the browser only for type and size; the server validates them.
 */
export function UniversalInput({
  busy,
  onText,
  onImage,
  onCamera,
  inputRef,
}: {
  busy: boolean
  onText: (text: string) => void
  onImage: (file: File) => void
  onCamera: () => void
  inputRef: React.RefObject<HTMLTextAreaElement | null>
}) {
  const [value, setValue] = useState('')
  const [problem, setProblem] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)
  const fieldId = useId()
  const fileId = useId()
  const detected = detectInput(value)

  function submit(event?: FormEvent) {
    event?.preventDefault()
    if (value.trim() && !busy) onText(value.trim())
  }

  function pick(file: File | undefined) {
    if (!file) return
    if (!ACCEPTED_IMAGE_TYPES.includes(file.type)) return setProblem('Please choose a PNG, JPEG or WEBP image.')
    if (file.size > MAX_UPLOAD_BYTES) return setProblem(`The image is ${formatBytes(file.size)}; the limit is 5 MB.`)
    setProblem(null)
    onImage(file)
  }

  return (
    <form onSubmit={submit} className="space-y-3" aria-label="Load a specimen">
      <label htmlFor={fieldId} className="label-mono block">
        Link, UPI ID or message
      </label>
      <div className="rounded-panel border border-line bg-panel p-2 focus-within:border-accent">
        <textarea
          id={fieldId}
          ref={inputRef}
          rows={2}
          value={value}
          maxLength={5000}
          spellCheck={false}
          autoComplete="off"
          placeholder="Paste a link, a UPI ID (name@bank) or the text of a message"
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && !event.shiftKey) {
              event.preventDefault()
              submit()
            }
          }}
          className="block w-full resize-y bg-transparent px-3 py-2 font-mono text-[15px] text-ink placeholder:font-sans placeholder:text-muted focus:outline-none"
        />
        <div className="flex flex-wrap items-center gap-2 border-t border-line px-1 pt-2">
          <span className="label-mono mr-auto px-2" data-testid="detected-type" aria-live="polite">
            {detected ? `Detected: ${SPECIMEN_LABEL[detected]}` : 'Detects link · UPI ID · message'}
          </span>
          <button type="button" className={secondaryButton} onClick={onCamera} disabled={busy}>
            <Icon name="camera" className="h-4 w-4" />
            Scan with camera
          </button>
          <label htmlFor={fileId} className={`${secondaryButton} cursor-pointer ${busy ? 'pointer-events-none opacity-50' : ''}`}>
            <Icon name="upload" className="h-4 w-4" />
            Upload QR or screenshot
          </label>
          <input
            id={fileId}
            ref={fileRef}
            type="file"
            accept={ACCEPTED_IMAGE_TYPES.join(',')}
            className="sr-only"
            disabled={busy}
            onChange={(event) => {
              pick(event.target.files?.[0])
              event.target.value = '' // the same file can be chosen again
            }}
          />
          <button type="submit" className={primaryButton} disabled={busy || !value.trim()}>
            Put in the airlock
          </button>
        </div>
      </div>
      {problem ? (
        <p role="alert" className="text-sm text-danger">
          {problem}
        </p>
      ) : null}
    </form>
  )
}
