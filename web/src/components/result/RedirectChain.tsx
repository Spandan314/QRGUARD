import { Icon } from '../Icon'

/** Where it leads: the addresses our server followed, ending where the link really goes. */
export function RedirectChain({ chain }: { chain: string[] }) {
  if (chain.length < 2) return null
  return (
    <section aria-labelledby="leads-title" className="rounded-panel border border-line bg-panel p-5" data-testid="redirect-chain">
      <h3 id="leads-title" className="font-display text-lg font-semibold">
        Where it leads
      </h3>
      <ol className="mt-3 flex flex-wrap items-center gap-2">
        {chain.map((hop, i) => (
          <li key={`${hop}-${i}`} className="flex items-center gap-2">
            {i > 0 ? <Icon name="arrow-right" className="h-4 w-4 text-muted" /> : null}
            <span
              className={`rounded-btn border px-3 py-1.5 font-mono text-sm break-all ${
                i === chain.length - 1 ? 'border-warn bg-warn/10 font-semibold text-warn' : 'border-line bg-panel-2'
              }`}
            >
              {hop}
            </span>
          </li>
        ))}
      </ol>
      <p className="mt-3 text-sm text-muted">We followed the link on our server, so you can see where it really goes without visiting it.</p>
    </section>
  )
}
