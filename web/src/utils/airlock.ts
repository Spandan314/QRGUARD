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
  ['decoded', 'Decoded'],
  ['unshortened', 'Unshortened'],
  ['inspected', 'Inspected'],
  ['threats', 'Threat lists'],
  ['verdict', 'Verdict'],
]

/** While the request runs: the server works on the first four together, the verdict waits. */
export function runningStages(): Stage[] {
  return STAGE_LABELS.map(([id, label]) =>
    id === 'verdict'
      ? { id, label, state: 'waiting', detail: 'waiting' }
      : { id, label, state: 'active', detail: 'on our server…' },
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
    return { id: 'decoded', label: 'Decoded', state: 'done', detail: type ? `QR → ${type === 'url' ? 'link' : type.toUpperCase()}` : 'QR read' }
  }
  if (result.input_type === 'screenshot') {
    const codes = a.qr_codes?.length ?? 0
    return { id: 'decoded', label: 'Decoded', state: 'done', detail: codes ? `text + ${codes} QR` : 'text read (OCR)' }
  }
  if (result.input_type === 'message') return { id: 'decoded', label: 'Decoded', state: 'done', detail: 'message read' }
  return { id: 'decoded', label: 'Decoded', state: 'done', detail: 'link read' }
}

function unshortened(result: AnalysisResult): Stage {
  const base = { id: 'unshortened' as const, label: 'Unshortened' }
  const destination = check(result, 'destination')
  if (destination) {
    const hops = result.analysis.redirects?.redirect_count ?? 0
    if (destination.status === 'completed') {
      return { ...base, state: 'done', detail: hops ? `${hops} redirect${hops === 1 ? '' : 's'}` : 'no redirect' }
    }
    if (destination.status === 'not_run') return { ...base, state: 'done', detail: 'not a short link' }
    return { ...base, state: 'warning', detail: 'could not follow' }
  }
  const links = result.analysis.links?.length ?? 0
  return { ...base, state: 'done', detail: links ? `${links} link${links === 1 ? '' : 's'} checked` : 'no links' }
}

function inspected(result: AnalysisResult): Stage {
  const signs = result.indicators.filter((i) => i.score_contribution > 0).length
  return signs
    ? { id: 'inspected', label: 'Inspected', state: 'warning', detail: `${signs} warning sign${signs === 1 ? '' : 's'}` }
    : { id: 'inspected', label: 'Inspected', state: 'done', detail: 'no warning signs' }
}

function threats(result: AnalysisResult): Stage {
  const base = { id: 'threats' as const, label: 'Threat lists' }
  const providers = uniqueProviders(result.threat_intel.providers)
  const states = providers.map(providerState)
  const flagged = states.filter((s) => s.outcome === 'flagged').length
  // QRGUARD's demo blocklist is demonstration data: never present it as a threat-list hit.
  const realFlags = providers.filter((p, i) => states[i]?.outcome === 'flagged' && !p.limited_coverage).length
  const checked = states.filter((s) => s.outcome === 'checked').length + flagged
  const failed = states.filter((s) => s.outcome === 'not_checked').length
  if (realFlags) return { ...base, state: 'warning', detail: `${realFlags} flagged it` }
  if (flagged) return { ...base, state: 'warning', detail: 'demo list only' }
  if (failed) return { ...base, state: 'warning', detail: `${failed} could not check` }
  if (!checked) return { ...base, state: 'warning', detail: 'none checked' }
  // "not listed" is not proof of safety, but the stage itself completed
  return { ...base, state: 'done', detail: `${checked} checked` }
}

function verdictStage(label: string): Stage {
  const warn = label === 'SUSPICIOUS' || label === 'MALICIOUS'
  return { id: 'verdict', label: 'Verdict', state: warn ? 'warning' : 'done', detail: label === 'UNVERIFIED' ? 'not verified' : label.toLowerCase() }
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
  if (result.input_type === 'qr' && a.qr) lines.push({ text: `QR decoded → ${a.qr.content_type}`, tone: 'normal' })
  if (result.input_type === 'screenshot') {
    lines.push({ text: `text read from the image (OCR quality: ${a.ocr?.quality ?? 'unknown'})`, tone: 'normal' })
  }
  const final = finalDestination(result)
  const hops = a.redirects?.redirect_count ?? 0
  if (final) lines.push({ text: `followed ${hops} redirect${hops === 1 ? '' : 's'} on our server → ${hostOf(final)}`, tone: 'warn' })
  else if (check(result, 'destination')?.status === 'not_run') lines.push({ text: 'not a short link: not followed', tone: 'normal' })

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
  if (unconfigured) lines.push({ text: `${unconfigured} threat source${unconfigured === 1 ? '' : 's'} not configured`, tone: 'normal' })

  const tone = verdictLabel === 'MALICIOUS' ? 'danger' : verdictLabel === 'SUSPICIOUS' ? 'warn' : 'normal'
  lines.push({ text: `verdict: ${verdictLabel === 'UNVERIFIED' ? 'NOT VERIFIED' : verdictLabel} · ${result.risk_score}/100`, tone })
  return lines
}
