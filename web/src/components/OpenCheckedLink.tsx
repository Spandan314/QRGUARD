import { useState } from 'react'
import type { VerdictLabel } from '../types/api'
import { hasUserInfo, hostOf, isOpenableUrl, linkAction } from '../utils/links'

const small =
  'inline-flex min-h-11 items-center rounded-btn border border-line px-3.5 text-sm font-medium text-ink hover:bg-panel-2'

/**
 * The only way the web app opens a checked link, and a deliberately small, secondary one: it is
 * offered only for SAFE and NOT VERIFIED results, never for SUSPICIOUS or MALICIOUS ones (those
 * only get "Copy link", for reporting). Nothing opens automatically: the user asks, sees the exact
 * host and address (and any redirect), and confirms. It opens exactly `url` (the analysed address)
 * in a new tab without an opener, never a corrected or similar domain. Non-web schemes and
 * user@host links are never opened.
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
  const [copied, setCopied] = useState(false)
  const action = linkAction(url, verdict)
  const canOpen = action === 'confirm' || action === 'caution'
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

  return (
    <section className="rounded-panel border border-line bg-panel-2 p-4" data-testid="open-checked-link">
      <h3 className="label-mono font-mono">The checked link</h3>
      <p className="mt-2 font-mono text-sm break-all">{url}</p>
      <div className="mt-3 flex flex-wrap gap-2">
        <button type="button" className={small} onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy link'}
        </button>
        {canOpen && !confirming ? (
          <button type="button" className={`${small} text-muted`} onClick={() => setConfirming(true)}>
            Open checked link
          </button>
        ) : null}
      </div>
      {action === 'never' ? (
        <p className="mt-2 text-sm text-muted" data-testid="never-open-reason">
          {hasUserInfo(url)
            ? 'This link hides its real address behind a name and "@", a common trick. QRGUARD does not open it.'
            : 'This is not a normal web link, so QRGUARD does not open it.'}
        </p>
      ) : null}
      {!canOpen && action !== 'never' ? (
        <p className="mt-2 text-sm text-muted" data-testid="never-open-reason">
          QRGUARD does not offer to open links it found suspicious. Copy it only to report it.
        </p>
      ) : null}
      {confirming ? (
        <div
          role="alertdialog"
          aria-labelledby="open-link-title"
          className="mt-3 rounded-panel border border-line bg-panel p-4 text-sm"
          data-testid="open-link-confirm"
        >
          <p id="open-link-title" className="font-semibold">
            You are about to open {host}
          </p>
          <p className="font-mono break-all">{url}</p>
          {finalUrl && finalUrl !== url ? (
            <p className="mt-1">
              This link redirects to: <span className="font-mono break-all">{finalUrl}</span>
            </p>
          ) : null}
          {action === 'caution' ? (
            <p className="mt-2 font-medium text-warn">
              QRGUARD could not verify this website. Do not enter passwords, OTPs or payment details unless you are sure it is
              genuine.
            </p>
          ) : null}
          <div className="mt-3 flex flex-wrap gap-2">
            {isOpenableUrl(url) ? (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                referrerPolicy="no-referrer"
                className="inline-flex min-h-11 items-center rounded-btn bg-accent px-4 text-sm font-semibold text-on-accent"
                data-testid="open-link-go"
                onClick={closeAfterOpening}
              >
                Open {host} in a new tab
              </a>
            ) : null}
            <button type="button" className={small} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
    </section>
  )
}
