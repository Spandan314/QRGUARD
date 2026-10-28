import type { AnalysisResult } from '../types/api'
import { formatBytes } from '../utils/format'
import { RiskBadge } from './RiskBadge'

// Every link and decoded value is rendered as plain text, never as a clickable <a href>.
function Plain({ children }: { children: string }) {
  return <span className="break-all font-mono text-sm">{children}</span>
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return '—'
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  return String(value)
}

export function AnalysisDetailsView({ result }: { result: AnalysisResult }) {
  const a = result.analysis
  const rows: { label: string; value: string }[] = []
  // A QR code holding a link shows that link once (as the QR content), not three times.
  const qrText = a.qr?.decoded_content
  if (a.normalized_url && a.normalized_url !== qrText) rows.push({ label: 'Checked address', value: a.normalized_url })
  if (a.redirects?.final_url && a.redirects.final_url !== a.normalized_url) {
    rows.push({ label: 'Redirects to', value: a.redirects.final_url })
  }
  const parsedRows = Object.entries(a.qr?.parsed ?? {}).filter(([, value]) => value !== qrText)
  const hasContent = rows.length > 0 || a.links?.length || a.ocr || a.qr || a.qr_codes?.length
  if (!hasContent) return null

  return (
    <details className="rounded-panel border border-line px-4 py-3" open={Boolean(a.qr || a.ocr)}>
      <summary className="cursor-pointer text-sm font-semibold text-ink">Technical details</summary>
      <div className="mt-3 space-y-4 text-sm">
        {rows.map((row) => (
          <p key={row.label}>
            <span className="text-muted">{row.label}: </span>
            <Plain>{row.value}</Plain>
          </p>
        ))}

        {a.qr ? (
          <div data-testid="qr-details">
            <p>
              <span className="text-muted">QR content ({a.qr.content_type}): </span>
              <Plain>{a.qr.decoded_content}</Plain>
            </p>
            {parsedRows.length > 0 ? (
              <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                {parsedRows.map(([key, value]) => (
                  <div key={key} className="contents">
                    <dt className="text-muted">{key.replaceAll('_', ' ')}</dt>
                    <dd className="break-all">{formatValue(value)}</dd>
                  </div>
                ))}
              </dl>
            ) : null}
          </div>
        ) : null}

        {a.qr_codes?.length ? (
          <div>
            <p className="font-medium">QR codes found in the image</p>
            <ul className="mt-1 space-y-1">
              {a.qr_codes.map((code) => (
                <li key={code.index} className="flex flex-wrap items-center gap-2">
                  {code.risk_level ? <RiskBadge verdict={code.risk_level === 'SAFE' ? 'UNVERIFIED' : code.risk_level} size="sm" /> : null}
                  <span className="text-muted">{code.content_type}</span>
                  <Plain>{code.decoded_content}</Plain>
                  {code.scored ? <span className="text-xs">(decided the result)</span> : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {a.links?.length ? (
          <div>
            <p className="font-medium">Links found</p>
            <ul className="mt-1 space-y-1">
              {a.links.map((link, index) => (
                <li key={`${link.url}-${index}`} className="flex flex-wrap items-center gap-2">
                  {link.risk_level ? <RiskBadge verdict={link.risk_level === 'SAFE' ? 'UNVERIFIED' : link.risk_level} size="sm" /> : null}
                  <Plain>{link.url}</Plain>
                  {link.found_in === 'qr' ? <span className="text-xs">(from a QR code)</span> : null}
                  {link.error ? <span className="text-xs text-muted">({link.error})</span> : null}
                </li>
              ))}
            </ul>
          </div>
        ) : null}

        {a.ocr ? (
          <div data-testid="ocr-details">
            <p className="font-medium">
              Text read from the image{' '}
              <span className="font-normal text-muted">
                (OCR quality: {a.ocr.quality}
                {a.ocr.confidence !== null ? `, ${Math.round(a.ocr.confidence)}%` : ''})
              </span>
            </p>
            <p className="mt-1 whitespace-pre-wrap break-words rounded bg-panel-2 p-2">
              {a.ocr.extracted_text}
            </p>
            <p className="mt-1 text-xs text-muted">
              Compare this with your screenshot: text recognition can misread letters.
            </p>
          </div>
        ) : null}

        {a.image ? (
          <p className="text-xs text-muted">
            Image: {a.image.format}, {a.image.width}×{a.image.height}, {formatBytes(a.image.size_bytes)}
          </p>
        ) : null}
      </div>
    </details>
  )
}
