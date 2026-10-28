import { useState } from 'react'
import type { AnalysisResult } from '../../types/api'
import { passData, type Stamp } from '../../utils/pass'
import { renderPassImage } from '../../utils/passImage'
import { Icon } from '../Icon'

const STAMP_CLASS: Record<Stamp, string> = {
  DANGER: 'border-stamp-denied text-stamp-denied',
  CAUTION: 'border-stamp-caution text-stamp-caution',
  SAFE: 'border-stamp-cleared text-stamp-cleared',
  'NOT VERIFIED': 'border-stamp-none text-stamp-none',
}

const button =
  'inline-flex min-h-11 items-center justify-center gap-2 rounded-btn px-4 text-sm font-semibold focus-visible:outline-2'

/**
 * The inspection pass: the verdict as a ticket people can share instead of the link. "Share the
 * pass" uses the Web Share API where there is one and copies the text otherwise; "Save as image"
 * draws the ticket on a canvas. The pass number is the server's request ID.
 */
export function InspectionPass({ result }: { result: AnalysisResult }) {
  const [checkedAt] = useState(() => new Date())
  const [status, setStatus] = useState<string | null>(null)
  const pass = passData(result, checkedAt)

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(pass.shareText)
      setStatus('Copied. Paste it into a chat or a family group.')
    } catch {
      setStatus('Could not copy it in this browser.')
    }
  }

  const share = async () => {
    if (typeof navigator.share === 'function') {
      try {
        await navigator.share({ title: `QRGUARD check ${pass.number}`, text: pass.shareText })
        setStatus('Shared.')
        return
      } catch (error) {
        if (error instanceof DOMException && error.name === 'AbortError') return // the user closed the share sheet
      }
    }
    await copy()
  }

  const save = async () => {
    const blob = await renderPassImage(pass).catch(() => null)
    if (!blob) {
      setStatus('Could not create the image in this browser.')
      return
    }
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `QRGUARD-check-${pass.number}.png`
    document.body.append(link)
    link.click()
    link.remove()
    window.setTimeout(() => URL.revokeObjectURL(url), 1000)
    setStatus('Image saved.')
  }

  return (
    <section aria-labelledby="pass-heading" className="grid grid-cols-1 items-start gap-6 md:grid-cols-[minmax(0,380px)_1fr]" data-testid="inspection-pass">
      <div role="group" aria-labelledby="pass-title" className="relative overflow-hidden rounded-panel bg-paper text-on-paper" data-testid="pass-ticket">
        <div className="space-y-4 px-5 pt-5 pb-4">
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
            <span className="font-display text-[15px] font-bold tracking-[0.06em]">
              QR<span className="text-stamp-cleared">GUARD</span>
            </span>
            <span className="font-mono text-[11px] tracking-[0.14em] text-on-paper-muted">SCAM CHECK RESULT</span>
          </div>
          <h4 id="pass-title" className="font-display text-2xl leading-tight font-bold break-words">
            {pass.title}
          </h4>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
            {pass.fields.map((field) => (
              <div key={field.label} className="min-w-0">
                <dt className="font-mono text-[10px] tracking-[0.14em] text-on-paper-muted">{field.label}</dt>
                <dd className="text-sm font-semibold break-words">{field.value}</dd>
              </div>
            ))}
          </dl>
        </div>
        <div aria-hidden="true" className="relative flex h-6 items-center">
          <span className="absolute -left-3 h-6 w-6 rounded-full bg-surface" />
          <span className="mx-[18px] flex-1 border-t-2 border-dashed border-[#cfc6b5]" />
          <span className="absolute -right-3 h-6 w-6 rounded-full bg-surface" />
        </div>
        <div className="flex items-center justify-between gap-3 px-5 pt-3 pb-5">
          <div className="min-w-0 space-y-1">
            <p className="font-mono text-[11px] tracking-[0.1em] whitespace-nowrap text-on-paper-muted" data-testid="pass-number">
              CHECK NO. {pass.number}
            </p>
            <p className="text-[13px] leading-snug">Checked on the QRGUARD server, not on the phone that scanned it.</p>
          </div>
          <p
            role="img"
            aria-label={`Result stamp: ${pass.stamp.toLowerCase()}`}
            className={`shrink-0 -rotate-12 rounded-[10px] border-4 px-2.5 py-0.5 font-display font-bold tracking-[0.12em] whitespace-nowrap ${pass.stamp.length > 8 ? 'text-base' : 'text-xl'} ${STAMP_CLASS[pass.stamp]}`}
            data-testid="pass-stamp"
          >
            {pass.stamp}
          </p>
        </div>
      </div>

      <div className="space-y-4">
        <div>
          <h3 id="pass-heading" className="font-display text-lg font-semibold">
            Share this result
          </h3>
          <p className="mt-1 text-sm text-muted">Send this card to family or friends instead of the link. It has no link anyone could tap by mistake.</p>
        </div>
        <p className="text-sm">{pass.advice}</p>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={`${button} bg-accent text-on-accent`} onClick={() => void share()} data-testid="share-pass">
            <Icon name="share" className="h-4 w-4" />
            Share the card
          </button>
          <button type="button" className={`${button} border border-line text-ink hover:bg-panel-2`} onClick={() => void save()} data-testid="save-pass">
            <Icon name="download" className="h-4 w-4" />
            Save as image
          </button>
        </div>
        <p role="status" className="min-h-5 text-sm text-muted" data-testid="pass-status">
          {status}
        </p>
      </div>
    </section>
  )
}
