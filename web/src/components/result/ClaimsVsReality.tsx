import type { ClaimRow } from '../../utils/result'
import { Icon } from '../Icon'

/**
 * Left: what the link presents itself as (warm paper). Right: what the server found. Middle: ≠ when
 * they differ (danger), = when they agree (accent). Only rows backed by facts from the API.
 */
export function ClaimsVsReality({ rows }: { rows: ClaimRow[] }) {
  if (!rows.length) return null
  const mismatches = rows.filter((r) => !r.matches).length
  return (
    <section aria-labelledby="claims-title" className="space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <h3 id="claims-title" className="font-display text-lg font-semibold">
          What it pretends to be vs what it really is
        </h3>
        <span
          className={`rounded-md border px-2 py-0.5 font-mono text-[11px] font-medium tracking-[0.14em] uppercase ${
            mismatches ? 'border-danger text-danger' : 'border-accent text-accent'
          }`}
          data-testid="mismatch-count"
        >
          {mismatches ? `${mismatches} of ${rows.length} don’t match` : 'Everything matches'}
        </span>
      </div>
      <div className="overflow-hidden rounded-panel-lg border border-line">
        {/* Below sm each row stacks: the claim on top, then =/≠ beside what we found. */}
        <table className="w-full border-collapse text-left">
          <thead className="hidden sm:table-header-group">
            <tr>
              <th scope="col" className="w-[46%] bg-paper px-5 py-3 font-display text-base font-semibold text-on-paper">
                <span className="inline-flex items-center gap-2">
                  <Icon name="eye" className="h-4 w-4" />
                  What it says
                </span>
              </th>
              <th scope="col" className="w-[8%] bg-panel-2 px-2 py-3 text-center font-mono text-xs font-normal text-muted">
                vs
              </th>
              <th scope="col" className="bg-panel px-5 py-3 font-display text-base font-semibold text-accent">
                <span className="inline-flex items-center gap-2">
                  <Icon name="search" className="h-4 w-4" />
                  What we found
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key} className="grid grid-cols-[2.75rem_1fr] border-t border-line first:border-t-0 sm:table-row sm:first:border-t" data-testid="claim-row" data-matches={row.matches}>
                <td className="col-span-2 bg-paper px-4 py-3 align-top text-on-paper sm:w-[46%] sm:px-5">
                  <span className="block font-mono text-[11px] tracking-[0.12em] text-on-paper-muted uppercase">
                    {row.label}
                    <span className="sm:hidden"> · what it says</span>
                  </span>
                  <span className={`mt-0.5 block font-semibold break-words ${row.key === 'address' ? 'font-mono text-sm' : ''}`}>{row.claim}</span>
                </td>
                <td className="flex items-center justify-center bg-panel-2 px-2 py-3 sm:table-cell sm:w-[8%] sm:text-center sm:align-middle">
                  <span className={`font-mono text-xl font-bold ${row.matches ? 'text-accent' : 'text-danger'}`} aria-hidden="true">
                    {row.matches ? '=' : '≠'}
                  </span>
                  <span className="sr-only">{row.matches ? 'matches' : 'does not match'}</span>
                </td>
                <td className="bg-panel px-4 py-3 align-top sm:px-5">
                  <span className="block font-mono text-[11px] tracking-[0.12em] text-muted uppercase">
                    {row.label}
                    <span className="sm:hidden"> · we found</span>
                  </span>
                  <span className="mt-0.5 block font-semibold break-words">{row.found}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}
