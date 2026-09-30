import { useId, useRef, useState, type DragEvent } from 'react'
import { ACCEPTED_IMAGE_TYPES, MAX_UPLOAD_BYTES } from '../services/api'
import { formatBytes } from '../utils/format'

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
        className={`flex min-h-36 cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed p-6 text-center transition ${
          dragging
            ? 'border-teal-600 bg-teal-50 dark:bg-teal-950'
            : 'border-slate-300 hover:border-teal-600 dark:border-slate-600'
        }`}
      >
        <span className="text-3xl" aria-hidden="true">
          🖼️
        </span>
        <span className="font-medium">{label}</span>
        <span className="text-sm text-slate-500 dark:text-slate-400">
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
        <p role="alert" className="mt-2 text-sm text-red-700 dark:text-red-300">
          {problem}
        </p>
      ) : null}
    </div>
  )
}
