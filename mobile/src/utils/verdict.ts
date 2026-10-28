// Display helper: which headline to show. The backend decides; this only reads its answer and,
// for older backends or history items (which store level + verification), applies the same rule:
// SAFE only when positively verified as a recognised website, otherwise UNVERIFIED.
import type { AnalysisResult, InputType, RiskLevel, Verdict, VerdictLabel, Verification } from '../types/api'

export function verdictLabel(level: RiskLevel, verification: Pick<Verification, 'status' | 'source'>): VerdictLabel {
  if (level !== 'SAFE') return level
  return verification.status === 'VERIFIED' && verification.source === 'trusted_domain_list' ? 'SAFE' : 'UNVERIFIED'
}

const TITLES: Record<VerdictLabel, string> = {
  MALICIOUS: 'Very likely malicious',
  SUSPICIOUS: 'Suspicious',
  SAFE: 'Recognised legitimate website',
  UNVERIFIED: 'Not verified – no known risks found',
}

export function verdictOf(result: Pick<AnalysisResult, 'verdict' | 'risk_level' | 'verification' | 'input_type'>): Verdict {
  if (result.verdict) return result.verdict
  const label = verdictLabel(result.risk_level, result.verification)
  const confirmed = label === 'MALICIOUS' && result.verification.source === 'threat_intelligence'
  const messageLike: InputType[] = ['message', 'screenshot']
  return {
    label,
    confirmed,
    title:
      label === 'UNVERIFIED' && messageLike.includes(result.input_type)
        ? 'No scam signs found – not verified'
        : confirmed
          ? 'Malicious – listed by threat intelligence'
          : TITLES[label],
    explanation: result.verification.message,
  }
}

export const NOT_CONFIRMED = 'Not confirmed by a threat-intelligence source.'

/**
 * The verification note under the verdict. A SUSPICIOUS or MALICIOUS result that no source has
 * confirmed says so plainly: the backend's generic "insufficient evidence" text (with its
 * caveat about SAFE results) is meant for SAFE and UNVERIFIED results and is not shown under a
 * warning. Its demo-blocklist note is kept, because it explains what the warning rests on.
 */
export function verificationNote(
  result: Pick<AnalysisResult, 'verification'>,
  verdict: Pick<Verdict, 'label' | 'evidence'>,
): { heading: string; message: string | null } {
  const { verification } = result
  const warning = verdict.label === 'SUSPICIOUS' || verdict.label === 'MALICIOUS'
  if (warning && verification.status !== 'VERIFIED') {
    return { heading: `❔ ${NOT_CONFIRMED}`, message: verdict.evidence === 'demo_blocklist' ? verification.message : null }
  }
  const heading =
    (verification.status === 'VERIFIED' ? '🔎 Verified' : '❔ Unverified') +
    (verification.source === 'threat_intelligence' ? ' by threat intelligence' : '') +
    (verification.source === 'trusted_domain_list' ? ' – recognised legitimate website' : '')
  return { heading, message: verification.message }
}
