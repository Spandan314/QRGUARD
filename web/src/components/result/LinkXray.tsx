import type { XrayPart } from '../../utils/result'

const PART: Record<XrayPart['kind'], { label: string; box: string; note: string }> = {
  scheme: { label: 'scheme', box: 'text-muted', note: 'text-muted' },
  subdomain: { label: 'subdomain (decoration)', box: 'bg-warn/15 text-warn', note: 'text-warn' },
  owner: { label: 'real owner', box: 'bg-accent/15 font-semibold text-accent', note: 'text-accent' },
  path: { label: 'path', box: 'text-muted', note: 'text-muted' },
}

function Marked({ part }: { part: XrayPart }) {
  if (!part.lookalikes.length) return <>{part.text}</>
  return (
    <>
      {[...part.text].map((char, i) =>
        part.lookalikes.includes(i) ? (
          <mark key={i} className="rounded-sm bg-danger px-px text-panel" title="Look-alike character">
            {char}
          </mark>
        ) : (
          <span key={i}>{char}</span>
        ),
      )}
    </>
  )
}

/** The link split into its parts. Read right to left: the owner is the part just before the path. */
export function LinkXray({ parts, notes }: { parts: XrayPart[]; notes: { title: string; text: string }[] }) {
  if (!parts.length) return null
  return (
    <section aria-labelledby="xray-title" className="space-y-3">
      <div>
        <h3 id="xray-title" className="font-display text-lg font-semibold">
          Link X-ray
        </h3>
        <p className="text-sm text-muted">The link split into its parts. Read from right to left to find who really owns it.</p>
      </div>
      <div className="overflow-x-auto rounded-panel border border-line bg-panel-2 p-4">
        <ol className="flex min-w-max items-start font-mono text-base sm:text-lg" data-testid="xray">
          {parts.map((part, index) => (
            <li key={part.kind} className="flex flex-col gap-1" data-part={part.kind}>
              <span className={`rounded-sm px-1 py-0.5 whitespace-pre ${PART[part.kind].box}`}>
                <Marked part={part} />
              </span>
              <span className={`px-1 font-sans text-[11px] ${PART[part.kind].note}`}>
                {index + 1} · {PART[part.kind].label}
              </span>
            </li>
          ))}
        </ol>
      </div>
      <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
        {notes.map((note, i) => (
          <div key={note.title}>
            <dt className="font-semibold">
              {i + 1} · {note.title}
            </dt>
            <dd className="mt-0.5 text-muted">{note.text}</dd>
          </div>
        ))}
      </dl>
    </section>
  )
}
