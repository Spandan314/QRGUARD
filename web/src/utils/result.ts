// The Airlock result page: "claims vs reality", the link X-ray, the score breakdown, the redirect
// chain and the official site. Everything is derived from facts in the API response; a row whose
// facts are missing is left out rather than guessed.
import officialDomains from 'virtual:official-domains'
import type { AnalysisResult, Indicator, VerdictLabel } from '../types/api'

// ---- Official site -------------------------------------------------------------------------------
/**
 * The brand's own website, when the link imitates a brand we know the official domain of.
 * Never the scanned link: a link that IS on the brand's domain gets no "real site" button.
 */
export function officialSite(result: AnalysisResult, domains: Record<string, string[]> = officialDomains): { brand: string; url: string; domain: string } | null {
  const brand = result.analysis.brand
  if (!brand || brand.match_type === 'official') return null
  const domain = domains[brand.brand]?.[0]
  return domain ? { brand: brand.brand, url: `https://${domain}/`, domain } : null
}

// ---- Claims vs reality ---------------------------------------------------------------------------
export interface ClaimRow {
  key: 'who' | 'address' | 'age' | 'asks' | 'padlock'
  label: string
  claim: string
  found: string
  /** true: what it claims matches what we found (=); false: it does not (≠). */
  matches: boolean
}

const has = (result: AnalysisResult, ...ids: string[]) => result.indicators.some((i) => ids.includes(i.id))
const warning = (label: VerdictLabel) => label === 'SUSPICIOUS' || label === 'MALICIOUS'

/** Words like "login", "verify", "kyc" found in the link (from the phishing-keyword indicators). */
export function linkWords(result: AnalysisResult): string[] {
  const words = result.indicators
    .filter((i) => i.id === 'URL_PHISHING_KEYWORD' && i.evidence)
    .map((i) => (i.evidence ?? '').replace(/^destination:\s*/, ''))
  return [...new Set(words)]
}

const ADDRESS_TRICKS = ['BRAND_LOOKALIKE', 'URL_PUNYCODE', 'URL_MIXED_SCRIPT', 'URL_DOMAIN_IN_SUBDOMAIN', 'OFFICIAL_DOMAIN_IN_SUBDOMAIN', 'URL_USERINFO_AT', 'BRAND_IN_SUBDOMAIN']

export function claimsVsReality(result: AnalysisResult, verdict: VerdictLabel): ClaimRow[] {
  const a = result.analysis
  if (!a.normalized_url || !a.host) return [] // only for links
  const rows: ClaimRow[] = []
  const owner = a.domain ?? a.host
  const brand = a.brand

  if (brand) {
    const own = brand.match_type === 'official'
    rows.push({
      key: 'who',
      label: 'Who it is',
      claim: brand.brand,
      found: own ? `${brand.brand}'s own domain (${owner})` : `A site on ${owner}`,
      matches: own,
    })
  }

  const shown = a.host_unicode ?? a.host
  const tricked = has(result, ...ADDRESS_TRICKS)
  rows.push({
    key: 'address',
    label: 'Address',
    claim: shown,
    found: tricked
      ? `The real owner is ${owner}${brand && brand.match_type !== 'official' ? `, not ${brand.brand}` : ''}`
      : a.subdomain
        ? `Owned by ${owner}`
        : `${owner}, as written`,
    matches: !tricked,
  })

  const age = a.domain_age
  if (brand && brand.match_type !== 'official' && age?.status === 'found' && age.age_days !== null) {
    const recent = age.age_days < 30
    rows.push({
      key: 'age',
      label: 'Age of the domain',
      claim: `${brand.brand}: an established organisation`,
      found: `${owner} was registered ${age.age_days} day${age.age_days === 1 ? '' : 's'} ago`,
      matches: !recent,
    })
  }

  const words = linkWords(result)
  if (words.length) {
    const suspicious = warning(verdict)
    rows.push({
      key: 'asks',
      label: 'What it asks for',
      claim: `“${words.join(' · ')}”`,
      found: suspicious ? 'Wording used to make a fake page look official' : 'Ordinary wording; no other warning signs',
      matches: !suspicious,
    })
  }

  if (a.scheme === 'https') {
    rows.push({
      key: 'padlock',
      label: 'Padlock / HTTPS',
      claim: warning(verdict) ? 'Padlock: looks “secure”' : 'Padlock (https)',
      found: 'The padlock only means encrypted, not honest',
      matches: !warning(verdict),
    })
  } else if (a.scheme === 'http') {
    rows.push({ key: 'padlock', label: 'Padlock / HTTPS', claim: 'No padlock (http)', found: 'Not encrypted: what you type can be read on the way', matches: false })
  }
  return rows
}

// ---- Link X-ray ----------------------------------------------------------------------------------
export interface XrayPart {
  kind: 'scheme' | 'subdomain' | 'owner' | 'path'
  text: string
  /** indices inside `text` of characters that imitate another (a digit for a letter, other scripts) */
  lookalikes: number[]
}

/** Digits standing in for letters ("nati0nal") and non-Latin characters are marked. */
export function lookalikeIndices(label: string): number[] {
  const marks: number[] = []
  for (let i = 0; i < label.length; i++) {
    const c = label.charAt(i)
    const between = /[0-9]/.test(c) && /[a-z]/i.test(label.charAt(i - 1)) && /[a-z]/i.test(label.charAt(i + 1))
    if (between || /[^\x20-\x7e]/.test(c)) marks.push(i)
  }
  return marks
}

export function linkXray(result: AnalysisResult): XrayPart[] {
  const a = result.analysis
  if (!a.normalized_url || !a.host || !a.domain || !a.scheme) return []
  const host = a.host_unicode ?? a.host
  let url: URL
  try {
    url = new URL(a.normalized_url)
  } catch {
    return []
  }
  const rest = `${url.port ? `:${url.port}` : ''}${url.pathname === '/' && !url.search ? '' : url.pathname}${url.search}`
  const ownerText = host.endsWith(a.domain) ? a.domain : host
  const sub = host.endsWith(a.domain) ? host.slice(0, host.length - a.domain.length) : ''
  const parts: XrayPart[] = [{ kind: 'scheme', text: `${a.scheme}://`, lookalikes: [] }]
  if (sub) parts.push({ kind: 'subdomain', text: sub, lookalikes: lookalikeIndices(sub) })
  parts.push({ kind: 'owner', text: ownerText, lookalikes: lookalikeIndices(ownerText) })
  if (rest) parts.push({ kind: 'path', text: rest, lookalikes: [] })
  return parts
}

// ---- Score breakdown -----------------------------------------------------------------------------
export interface BreakdownRow {
  label: string
  points: number
}

/** "Why <score>": every sign that added (or removed) points, the floor if one applied, the total. */
export function scoreBreakdown(result: AnalysisResult): { rows: BreakdownRow[]; total: number } {
  const titleOf = (id: string) => result.indicators.find((i: Indicator) => i.id === id)?.title ?? id
  const rows = result.indicators
    .filter((i) => Math.round(i.score_contribution * 10) !== 0)
    .sort((x, y) => y.score_contribution - x.score_contribution)
    .map((i) => ({ label: i.evidence ? `${i.title} (${i.evidence.replace(/^destination:\s*/, '')})` : i.title, points: i.score_contribution }))
  const floor = result.score_breakdown?.floor_applied
  if (floor && floor.points_added > 0) {
    rows.push({ label: `Minimum score for “${titleOf(floor.indicator)}”`, points: floor.points_added })
  }
  return { rows, total: result.risk_score }
}

// ---- Redirect chain ------------------------------------------------------------------------------
/** The addresses the server followed, ending where the link really leads. */
export function redirectChain(result: AnalysisResult): string[] {
  const r = result.analysis.redirects
  if (!r?.checked) return []
  const urls = [...(r.hops ?? []).map((h) => h.url), ...(r.final_url ? [r.final_url] : [])]
  const chain: string[] = []
  for (const url of urls) {
    let shown = url
    try {
      const u = new URL(url)
      shown = `${u.host}${u.pathname === '/' ? '' : u.pathname}`
    } catch {
      // keep as is
    }
    if (chain.at(-1) !== shown) chain.push(shown)
  }
  return chain.length > 1 ? chain : []
}

/** The four numbered notes under the X-ray, from facts only. */
export function xrayNotes(result: AnalysisResult, parts: XrayPart[], verdict: VerdictLabel): { title: string; text: string }[] {
  const a = result.analysis
  const notes: { title: string; text: string }[] = []
  for (const part of parts) {
    if (part.kind === 'scheme') {
      notes.push(
        a.scheme === 'https'
          ? { title: 'HTTPS', text: 'Only means the connection is encrypted. Scam sites use it too.' }
          : { title: a.scheme?.toUpperCase() ?? 'Scheme', text: a.scheme === 'http' ? 'Not encrypted: what you type can be read on the way.' : 'Not a normal web address.' },
      )
    } else if (part.kind === 'subdomain') {
      notes.push(
        part.lookalikes.length
          ? { title: 'Look-alike name', text: 'Uses a digit or a foreign letter in place of a normal letter. Anything left of the owner can be typed freely.' }
          : { title: 'Decoration', text: 'Anything left of the owner can be typed freely by whoever owns the domain.' },
      )
    } else if (part.kind === 'owner') {
      const brand = a.brand
      const notBrand = brand && brand.match_type !== 'official' ? `, not ${brand.brand}` : ''
      const age = a.domain_age?.status === 'found' && a.domain_age.age_days !== null ? ` Registered ${a.domain_age.age_days} days ago.` : ''
      notes.push({
        title: part.lookalikes.length ? 'Look-alike owner' : 'Who owns it',
        text: `${a.domain}${notBrand}.${age}`,
      })
    } else {
      const words = linkWords(result)
      notes.push(
        words.length && warning(verdict)
          ? { title: 'Wording', text: `“${words.join(', ')}” pages are a common way to steal logins and OTPs.` }
          : { title: 'Path', text: 'The page on that website.' },
      )
    }
  }
  return notes
}
