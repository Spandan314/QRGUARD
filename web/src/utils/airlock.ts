// The Airlock check page: what was put in (the "specimen"), the five chamber stages and the
// chamber log. Everything here is derived from the user's input and the REAL analysis response;
// the web app makes no security decisions of its own.
import type { AnalysisResult, Check } from '../types/api'
import { PROVIDER_NAME } from './format'
import { providerState, uniqueProviders } from './providerStatus'

// ---- Input -------------------------------------------------------------------------------------
export type SpecimenKind = 'link' | 'upi' | 'message' | 'image' | 'camera'

export interface Specimen {
  kind: SpecimenKind
  /** What the user gave (text) or the file name (image). Shown only on this device. */
  text: string
}

const URL_SCHEME = /^(https?|upi|tel|mailto|wifi|ftp|data|javascript):/i
// a single token that looks like a host name with a dot, optionally with a path
const BARE_HOST = /^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?::\d{1,5})?(?:[/?#]\S*)?$/i
// UPI virtual payment address: handle@psp (the PSP part has no dot, unlike an e-mail domain)
const UPI_ID = /^[a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9-]{1,63}$/i

/** Classifies what was typed or pasted into the one input field. */
export function detectInput(raw: string): 'link' | 'upi' | 'message' | null {
  const value = raw.trim()
  if (!value) return null
  if (/\s/.test(value)) return 'message' // more than one word: a message (its links are checked too)
  if (UPI_ID.test(value)) return 'upi'
  if (URL_SCHEME.test(value) || BARE_HOST.test(value)) return 'link'
  return 'message'
}

export const SPECIMEN_LABEL: Record<SpecimenKind, string> = {
  link: 'link',
  upi: 'UPI ID',
  message: 'message',
  image: 'image',
  camera: 'QR code',
}

/** "upi://pay?pa=…" for a bare UPI ID, so it is checked exactly like a scanned payment QR code. */
export function upiPayload(id: string): string {
  return `upi://pay?pa=${encodeURIComponent(id.trim())}`
}

// ---- Stages ------------------------------------------------------------------------------------
export type StageState = 'done' | 'warning' | 'active' | 'waiting'

export interface Stage {
  id: 'decoded' | 'unshortened' | 'inspected' | 'threats' | 'verdict'
  label: string
  state: StageState
  detail: string
}

const STAGE_LABELS: [Stage['id'], string][] = [
  ['decoded', 'Read it'],
  ['unshortened', 'Followed the link'],
  ['inspected', 'Warning signs'],
  ['threats', 'Scam databases'],
  ['verdict', 'Result'],
]

/** While the request runs: the server works on the first four together, the verdict waits. */
export function runningStages(): Stage[] {
  return STAGE_LABELS.map(([id, label]) =>
    id === 'verdict'
      ? { id, label, state: 'waiting', detail: 'waiting' }
      : { id, label, state: 'active', detail: 'checking…' },
  )
}

export function idleStages(): Stage[] {
  return STAGE_LABELS.map(([id, label]) => ({ id, label, state: 'waiting', detail: '—' }))
}

const check = (result: AnalysisResult, id: string): Check | undefined => result.checks?.find((c) => c.id === id)

function decoded(result: AnalysisResult): Stage {
  const a = result.analysis
  if (result.input_type === 'qr') {
    const type = a.qr?.content_type
    return { id: 'decoded', label: 'Read it', state: 'done', detail: type === 'url' ? 'QR code with a link' : type === 'upi' ? 'QR code for a UPI payment' : 'QR code read' }
  }
  if (result.input_type === 'screenshot') {
    const codes = a.qr_codes?.length ?? 0
    return { id: 'decoded', label: 'Read it', state: 'done', detail: codes ? `text and ${codes} QR code${codes === 1 ? '' : 's'} read` : 'text read from the image' }
  }
  if (result.input_type === 'message') return { id: 'decoded', label: 'Read it', state: 'done', detail: 'message read' }
  return { id: 'decoded', label: 'Read it', state: 'done', detail: 'link read' }
}

function unshortened(result: AnalysisResult): Stage {
  const base = { id: 'unshortened' as const, label: 'Followed the link' }
  const destination = check(result, 'destination')
  if (destination) {
    const hops = result.analysis.redirects?.redirect_count ?? 0
    if (destination.status === 'completed') {
      return { ...base, state: 'done', detail: hops ? `sent on to ${hops} other page${hops === 1 ? '' : 's'}` : 'goes straight to the page' }
    }
    if (destination.status === 'not_run') return { ...base, state: 'done', detail: 'not a short link, no need' }
    return { ...base, state: 'warning', detail: 'could not follow it' }
  }
  const links = result.analysis.links?.length ?? 0
  return { ...base, state: 'done', detail: links ? `${links} link${links === 1 ? '' : 's'} checked` : 'no links' }
}

function inspected(result: AnalysisResult): Stage {
  const signs = result.indicators.filter((i) => i.score_contribution > 0).length
  return signs
    ? { id: 'inspected', label: 'Warning signs', state: 'warning', detail: `${signs} found` }
    : { id: 'inspected', label: 'Warning signs', state: 'done', detail: 'none found' }
}

function threats(result: AnalysisResult): Stage {
  const base = { id: 'threats' as const, label: 'Scam databases' }
  const providers = uniqueProviders(result.threat_intel.providers)
  const states = providers.map(providerState)
  const flagged = states.filter((s) => s.outcome === 'flagged').length
  // QRGUARD's demo blocklist is demonstration data: never present it as a threat-list hit.
  const realFlags = providers.filter((p, i) => states[i]?.outcome === 'flagged' && !p.limited_coverage).length
  const checked = states.filter((s) => s.outcome === 'checked').length + flagged
  const failed = states.filter((s) => s.outcome === 'not_checked').length
  if (realFlags) return { ...base, state: 'warning', detail: `on ${realFlags} scam list${realFlags === 1 ? '' : 's'}` }
  if (flagged) return { ...base, state: 'warning', detail: 'on our test list only' }
  if (failed) return { ...base, state: 'warning', detail: `${failed} did not answer` }
  if (!checked) return { ...base, state: 'warning', detail: 'none answered' }
  // "not listed" is not proof of safety, but the stage itself completed
  return { ...base, state: 'done', detail: `not on ${checked} list${checked === 1 ? '' : 's'}` }
}

function verdictStage(label: string): Stage {
  const warn = label === 'SUSPICIOUS' || label === 'MALICIOUS'
  return { id: 'verdict', label: 'Result', state: warn ? 'warning' : 'done', detail: label === 'UNVERIFIED' ? 'not verified' : label.toLowerCase() }
}

/** The five stages as the real response reports them. */
export function finishedStages(result: AnalysisResult, verdictLabel: string): Stage[] {
  return [decoded(result), unshortened(result), inspected(result), threats(result), verdictStage(verdictLabel)]
}

// ---- Final destination -------------------------------------------------------------------------
/** Where the link really leads after redirects, when that differs from what was put in. */
export function finalDestination(result: AnalysisResult): string | null {
  const final = result.analysis.redirects?.final_url
  return final && final !== result.analysis.normalized_url ? final : null
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname
  } catch {
    return url
  }
}

const words = (text: string) =>
  text
    .toLowerCase()
    .replace(/'s\b/g, '')
    .split(/[^a-z0-9]+/)
    .filter((w) => w.length > 2)

/** True when every word of the evidence is already in the title (nothing new to show). */
function repeats(title: string, evidence: string): boolean {
  const inTitle = new Set(words(title))
  const ev = words(evidence)
  return ev.length > 0 && ev.every((w) => inTitle.has(w))
}

// ---- Chamber log -------------------------------------------------------------------------------
export interface LogLine {
  text: string
  tone: 'normal' | 'warn' | 'danger'
}

/** Plain monospace lines built from the findings, in the order the chamber works. */
export function chamberLog(result: AnalysisResult, verdictLabel: string): LogLine[] {
  const lines: LogLine[] = []
  const a = result.analysis
  if (result.input_type === 'qr' && a.qr) lines.push({ text: `QR code read: ${a.qr.content_type === 'url' ? 'a link' : a.qr.content_type === 'upi' ? 'a UPI payment' : a.qr.content_type}`, tone: 'normal' })
  if (result.input_type === 'screenshot') {
    lines.push({ text: `text read from the image (quality: ${a.ocr?.quality ?? 'unknown'})`, tone: 'normal' })
  }
  const final = finalDestination(result)
  const hops = a.redirects?.redirect_count ?? 0
  if (final) lines.push({ text: `the link sends you on to ${hostOf(final)} (${hops} step${hops === 1 ? '' : 's'}, followed on our server)`, tone: 'warn' })
  else if (check(result, 'destination')?.status === 'not_run') lines.push({ text: 'not a short link, so nothing to follow', tone: 'normal' })

  const signs = [...result.indicators].filter((i) => i.score_contribution > 0).sort((x, y) => y.score_contribution - x.score_contribution)
  for (const sign of signs.slice(0, 6)) {
    const title = sign.title.toLowerCase()
    const evidence = sign.evidence && !repeats(title, sign.evidence) ? sign.evidence : null
    lines.push({ text: evidence ? `${title}: ${evidence}` : title, tone: sign.score_contribution >= 25 ? 'danger' : 'warn' })
  }
  if (signs.length > 6) lines.push({ text: `+ ${signs.length - 6} more warning signs`, tone: 'warn' })

  const providers = uniqueProviders(result.threat_intel.providers)
  for (const p of providers) {
    const state = providerState(p)
    if (state.outcome === 'not_configured') continue
    lines.push({
      text: `${(PROVIDER_NAME[p.provider] ?? p.provider).toLowerCase()}: ${state.label.toLowerCase()}`,
      tone: state.outcome === 'flagged' ? 'danger' : state.outcome === 'not_checked' ? 'warn' : 'normal',
    })
  }
  const unconfigured = providers.filter((p) => providerState(p).outcome === 'not_configured').length
  if (unconfigured) lines.push({ text: `${unconfigured} scam database${unconfigured === 1 ? '' : 's'} not set up`, tone: 'normal' })

  const tone = verdictLabel === 'MALICIOUS' ? 'danger' : verdictLabel === 'SUSPICIOUS' ? 'warn' : 'normal'
  lines.push({ text: `result: ${verdictLabel === 'UNVERIFIED' ? 'NOT VERIFIED' : verdictLabel} · risk ${result.risk_score} out of 100`, tone })
  return lines
}
