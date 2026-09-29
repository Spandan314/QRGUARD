import QRCode from 'qrcode'
import { useState, type FormEvent, type ReactNode } from 'react'
import { buttonClass, inputClass } from '../components/CheckPage'
import { buildPayload, PayloadError, type QrInput, type QrKind, type WifiSecurity } from '../utils/qrPayload'

const KINDS: { value: QrKind; label: string }[] = [
  { value: 'url', label: 'Link' },
  { value: 'text', label: 'Text' },
  { value: 'wifi', label: 'Wi-Fi' },
  { value: 'email', label: 'E-mail' },
  { value: 'phone', label: 'Phone' },
]

interface Generated {
  png: string
  svg: string
}

function Field({ id, label, children }: { id: string; label: string; children: ReactNode }) {
  return (
    <div className="space-y-1">
      <label htmlFor={id} className="block font-medium">
        {label}
      </label>
      {children}
    </div>
  )
}

export default function QrGenerator() {
  const [kind, setKind] = useState<QrKind>('url')
  const [input, setInput] = useState<QrInput>({ security: 'WPA' })
  const [generated, setGenerated] = useState<Generated | null>(null)
  const [error, setError] = useState<string | null>(null)

  const set = (key: keyof QrInput) => (event: { target: { value: string } }) =>
    setInput((current) => ({ ...current, [key]: event.target.value }))

  async function submit(event: FormEvent) {
    event.preventDefault()
    setGenerated(null)
    try {
      const payload = buildPayload(kind, input)
      const options = { errorCorrectionLevel: 'M' as const, margin: 4, width: 512 }
      const [png, svg] = await Promise.all([
        QRCode.toDataURL(payload, options),
        QRCode.toString(payload, { ...options, type: 'svg' }),
      ])
      setGenerated({ png, svg: `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}` })
      setError(null)
    } catch (caught) {
      setError(caught instanceof PayloadError ? caught.message : 'This content is too long for a QR code.')
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Make a QR code</h1>
        <p className="mt-2 text-slate-600 dark:text-slate-300">
          The code is created in your browser. Nothing you type here – including Wi-Fi passwords – is sent to
          QRGUARD.
        </p>
      </div>
      <form
        onSubmit={submit}
        className="space-y-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900"
      >
        <fieldset>
          <legend className="mb-2 font-medium">Type</legend>
          <div className="flex flex-wrap gap-2">
            {KINDS.map((option) => (
              <label key={option.value} className="flex min-h-11 items-center gap-2 rounded-lg border border-slate-300 px-3 dark:border-slate-600">
                <input
                  type="radio"
                  name="kind"
                  value={option.value}
                  checked={kind === option.value}
                  onChange={() => {
                    setKind(option.value)
                    setGenerated(null)
                    setError(null)
                  }}
                />
                {option.label}
              </label>
            ))}
          </div>
        </fieldset>

        {kind === 'url' ? (
          <Field id="gen-url" label="Link to encode">
            <input id="gen-url" className={inputClass} placeholder="https://example.com" value={input.url ?? ''} onChange={set('url')} />
          </Field>
        ) : null}
        {kind === 'text' ? (
          <Field id="gen-text" label="Text to encode">
            <textarea id="gen-text" rows={4} maxLength={1000} className={inputClass} value={input.text ?? ''} onChange={set('text')} />
          </Field>
        ) : null}
        {kind === 'wifi' ? (
          <>
            <Field id="gen-ssid" label="Network name (SSID)">
              <input id="gen-ssid" className={inputClass} maxLength={32} value={input.ssid ?? ''} onChange={set('ssid')} />
            </Field>
            <Field id="gen-security" label="Security">
              <select
                id="gen-security"
                className={inputClass}
                value={input.security}
                onChange={(event) => setInput((c) => ({ ...c, security: event.target.value as WifiSecurity }))}
              >
                <option value="WPA">WPA / WPA2</option>
                <option value="WPA3">WPA3</option>
                <option value="WEP">WEP (weak)</option>
                <option value="nopass">None (open network)</option>
              </select>
            </Field>
            {input.security !== 'nopass' ? (
              <Field id="gen-password" label="Password">
                <input
                  id="gen-password"
                  type="password"
                  autoComplete="off"
                  className={inputClass}
                  value={input.password ?? ''}
                  onChange={set('password')}
                />
              </Field>
            ) : null}
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={input.hidden ?? false}
                onChange={(event) => setInput((c) => ({ ...c, hidden: event.target.checked }))}
              />
              Hidden network
            </label>
          </>
        ) : null}
        {kind === 'email' ? (
          <>
            <Field id="gen-to" label="E-mail address">
              <input id="gen-to" type="email" className={inputClass} value={input.to ?? ''} onChange={set('to')} />
            </Field>
            <Field id="gen-subject" label="Subject (optional)">
              <input id="gen-subject" className={inputClass} maxLength={200} value={input.subject ?? ''} onChange={set('subject')} />
            </Field>
            <Field id="gen-body" label="Message (optional)">
              <textarea id="gen-body" rows={3} maxLength={1000} className={inputClass} value={input.body ?? ''} onChange={set('body')} />
            </Field>
          </>
        ) : null}
        {kind === 'phone' ? (
          <Field id="gen-number" label="Phone number">
            <input id="gen-number" type="tel" className={inputClass} value={input.number ?? ''} onChange={set('number')} />
          </Field>
        ) : null}

        <button type="submit" className={buttonClass}>
          Create QR code
        </button>
        {error ? (
          <p role="alert" className="text-sm text-red-700 dark:text-red-300">
            {error}
          </p>
        ) : null}
      </form>

      {generated ? (
        <div className="flex flex-col items-center gap-4 rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-900">
          <img src={generated.png} alt="Generated QR code" className="h-64 w-64 bg-white" />
          <div className="flex gap-3">
            <a className={buttonClass} href={generated.png} download="qrguard-qr.png">
              Download PNG
            </a>
            <a className={buttonClass} href={generated.svg} download="qrguard-qr.svg">
              Download SVG
            </a>
          </div>
        </div>
      ) : null}
    </div>
  )
}
