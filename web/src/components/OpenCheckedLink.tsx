import { useState } from 'react'
import type { VerdictLabel } from '../types/api'
import { hasUserInfo, hostOf, isOpenableUrl, linkAction } from '../utils/links'

const button =
  'rounded-lg px-4 py-2 text-sm font-semibold focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2'

/**
 * The only way the web app opens a checked link. Nothing is opened automatically: the user asks,
 * sees the exact host and address (and any redirect), and confirms. It opens exactly `url` (the
 * analysed, normalised address) in a new tab without an opener, never a corrected or similar
 * domain. Non-web schemes and user@host links are never opened.
 *
 * The confirmation is a real link (<a target="_blank" rel="noopener noreferrer">) that the user
 * clicks, not a scripted window.open(): browsers, extensions and in-app browsers may block a
 * scripted popup, and with "noopener" window.open() returns null even on success, so a blocked
 * popup cannot be detected and the click would silently do nothing.
 */
export function OpenCheckedLink({
  url,
  verdict,
  finalUrl,
}: {
  url: string
  verdict: VerdictLabel
  finalUrl?: string | null
}) {
  const [confirming, setConfirming] = useState(false)
  const [understood, setUnderstood] = useState(false)
  const [copied, setCopied] = useState(false)
  const action = linkAction(url, verdict)
  const host = hostOf(url)

  // Close only after the browser has followed the link (the click's default action).
  const closeAfterOpening = () => window.setTimeout(() => setConfirming(false), 0)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(url)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  const warning = {
    confirm: null,
    caution:
      'QRGUARD could not verify this website. Do not enter passwords, OTPs or payment details unless you are sure it is genuine.',
    warn: 'This link looks suspicious. Only continue if you trust the sender.',
    'copy-only': 'This link is very likely a scam or an attack. QRGUARD strongly advises not to open it.',
    never: null,
  }[action]

  return (
    <section className="rounded-md border border-slate-200 p-4 dark:border-slate-700" data-testid="open-checked-link">
      <h3 className="mb-1 font-semibold">The checked link</h3>
      <p className="break-all font-mono text-sm">{url}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className={`${button} bg-slate-100 text-slate-900 dark:bg-slate-800 dark:text-slate-100`} onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy link'}
        </button>
        {action !== 'never' && !confirming ? (
          <button
            type="button"
            className={`${button} ${action === 'confirm' || action === 'caution' ? 'bg-teal-700 text-white hover:bg-teal-800' : 'border border-red-300 bg-white text-red-700 hover:bg-red-50 dark:border-red-800 dark:bg-transparent dark:text-red-300'}`}
            onClick={() => {
              setUnderstood(false)
              setConfirming(true)
            }}
          >
            {action === 'copy-only' ? 'Open checked link (not recommended)' : 'Open checked link'}
          </button>
        ) : null}
      </div>
      {action === 'never' ? (
        <p className="mt-2 text-sm text-slate-700 dark:text-slate-300" data-testid="never-open-reason">
          {hasUserInfo(url)
            ? 'This link hides its real address behind a name and "@", a common trick. QRGUARD does not open it.'
            : 'This is not a normal web link, so QRGUARD does not open it.'}
        </p>
      ) : null}
      {confirming ? (
        <div role="alertdialog" aria-labelledby="open-link-title" className="mt-3 rounded-md border border-slate-200 bg-slate-50 p-3 dark:border-slate-700 text-sm dark:bg-slate-800" data-testid="open-link-confirm">
          <p id="open-link-title" className="font-semibold">
            You are about to open {host}
          </p>
          <p className="break-all font-mono">{url}</p>
          {finalUrl && finalUrl !== url ? (
            <p className="mt-1">
              This link redirects to: <span className="break-all font-mono">{finalUrl}</span>
            </p>
          ) : null}
          {warning ? <p className="mt-2 font-medium">{warning}</p> : null}
          {action === 'copy-only' ? (
            <label className="mt-2 flex items-center gap-2">
              <input type="checkbox" checked={understood} onChange={(event) => setUnderstood(event.target.checked)} />
              I understand this link is very likely dangerous
            </label>
          ) : null}
          <div className="mt-3 flex flex-wrap gap-2">
            {action === 'copy-only' && !understood ? (
              <button type="button" className={`${button} bg-red-700 text-white disabled:opacity-50`} disabled>
                Open {host} in a new tab
              </button>
            ) : isOpenableUrl(url) ? (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                referrerPolicy="no-referrer"
                className={`${button} inline-block ${action === 'copy-only' || action === 'warn' ? 'bg-red-700 text-white' : 'bg-teal-700 text-white'}`}
                data-testid="open-link-go"
                onClick={closeAfterOpening}
              >
                Open {host} in a new tab
              </a>
            ) : null}
            <button type="button" className={`${button} bg-slate-200 text-slate-900 dark:bg-slate-700 dark:text-slate-100`} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
    </section>
  )
}
