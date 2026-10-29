import { useId, useRef, useState, type DragEvent } from 'react'
import { ACCEPTED_IMAGE_TYPES, MAX_UPLOAD_BYTES } from '../services/api'
import { formatBytes } from '../utils/format'
import { Icon } from './Icon'

interface Props {
  label: string
  file: File | null
  onFile: (file: File | null) => void
  disabled?: boolean
}

/** Convenience checks only (type and size); the backend validates the file content itself. */
export function FileDropzone({ label, file, onFile, disabled = false }: Props) {
  const inputId = useId()
  const inputRef = useRef<HTMLInputElement>(null)
  const [problem, setProblem] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)

  function accept(candidate: File | undefined) {
    if (!candidate) return
    if (!ACCEPTED_IMAGE_TYPES.includes(candidate.type)) {
      setProblem('Please choose a PNG, JPEG or WEBP image.')
      onFile(null)
      return
    }
    if (candidate.size > MAX_UPLOAD_BYTES) {
      setProblem(`The image is ${formatBytes(candidate.size)}; the limit is 5 MB.`)
      onFile(null)
      return
    }
    setProblem(null)
    onFile(candidate)
  }

  function onDrop(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault()
    setDragging(false)
    if (!disabled) accept(event.dataTransfer.files[0])
  }

  return (
    <div>
      <label
        htmlFor={inputId}
        onDragOver={(event) => {
          event.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={`flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 rounded-panel border border-dashed p-6 text-center transition ${
          dragging
            ? 'border-accent bg-accent/10'
            : 'border-line bg-panel-2/60 hover:border-accent'
        }`}
      >
        <span className="flex h-10 w-10 items-center justify-center rounded-full bg-panel-2 text-muted">
          <Icon name="upload" />
        </span>
        <span className="font-medium">{label}</span>
        <span className="text-sm text-muted">
          Drag and drop or click to choose · PNG, JPEG or WEBP · max 5 MB
        </span>
        {file ? (
          <span className="text-sm font-medium" data-testid="selected-file">
            Selected: {file.name} ({formatBytes(file.size)})
          </span>
        ) : null}
      </label>
      <input
        ref={inputRef}
        id={inputId}
        type="file"
        accept={ACCEPTED_IMAGE_TYPES.join(',')}
        className="sr-only"
        disabled={disabled}
        onChange={(event) => {
          accept(event.target.files?.[0])
          event.target.value = ''
        }}
      />
      {problem ? (
        <p role="alert" className="mt-2 text-sm text-danger">
          {problem}
        </p>
      ) : null}
    </div>
  )
}
