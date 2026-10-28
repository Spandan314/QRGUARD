import { maliciousUrl, safeUnverified } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { claimsVsReality, linkXray, lookalikeIndices, officialSite, redirectChain, scoreBreakdown, xrayNotes } from './result'

const DOMAINS = { 'State Bank of India': ['sbi.co.in', 'onlinesbi.sbi'] }

const lookalike: AnalysisResult = {
  ...maliciousUrl,
  indicators: [
    ...maliciousUrl.indicators,
    { id: 'URL_PHISHING_KEYWORD', severity: 'medium', title: 'Login wording', message: 'm', evidence: 'login', weight: 10, score_contribution: 10, module: 'url_qr' },
    { id: 'URL_PHISHING_KEYWORD', severity: 'medium', title: 'Login wording', message: 'm', evidence: 'destination: login', weight: 0, score_contribution: 0, module: 'url_qr' },
  ],
  analysis: {
    normalized_url: 'https://sbi.co.in.kyc-verify.xyz/login',
    scheme: 'https',
    host: 'sbi.co.in.kyc-verify.xyz',
    domain: 'kyc-verify.xyz',
    subdomain: 'sbi.co.in',
    brand: { brand: 'State Bank of India', match_type: 'impersonation' },
    domain_age: { domain: 'kyc-verify.xyz', status: 'found', registered: '2026-10-20', age_days: 8 },
    redirects: { checked: false },
  },
}

describe('officialSite', () => {
  it("offers the brand's own site for an imitation, never the scanned link", () => {
    expect(officialSite(lookalike, DOMAINS)).toEqual({ brand: 'State Bank of India', url: 'https://sbi.co.in/', domain: 'sbi.co.in' })
  })

  it('offers nothing for the brand itself, unknown brands or no brand', () => {
    const own = { ...lookalike, analysis: { ...lookalike.analysis, brand: { brand: 'State Bank of India', match_type: 'official' } } }
    expect(officialSite(own, DOMAINS)).toBeNull()
    const unknown = { ...lookalike, analysis: { ...lookalike.analysis, brand: { brand: 'Nobody', match_type: 'lookalike' } } }
    expect(officialSite(unknown, DOMAINS)).toBeNull()
    expect(officialSite(maliciousUrl, DOMAINS)).toBeNull()
  })

  it('reads the official domains built from brands.yaml by default', () => {
    expect(officialSite(lookalike)?.domain).toBe('sbi.co.in')
  })
})

describe('claimsVsReality', () => {
  it('compares each claim with the facts found', () => {
    const rows = claimsVsReality(lookalike, 'MALICIOUS')
    expect(rows.map((r) => [r.key, r.matches])).toEqual([
      ['who', false],
      ['address', false],
      ['age', false],
      ['asks', false],
      ['padlock', false],
    ])
    expect(rows[1]?.found).toBe('The real owner is kyc-verify.xyz, not State Bank of India')
    expect(rows[2]?.found).toBe('kyc-verify.xyz was registered 8 days ago')
    expect(rows[3]?.claim).toBe('“login”') // the same word from the destination is not repeated
  })

  it('leaves out rows without facts', () => {
    const plain: AnalysisResult = {
      ...safeUnverified,
      analysis: { normalized_url: 'https://example.com/', scheme: 'https', host: 'example.com', domain: 'example.com' },
    }
    const rows = claimsVsReality(plain, 'UNVERIFIED')
    expect(rows.map((r) => r.key)).toEqual(['address', 'padlock'])
    expect(rows.every((r) => r.matches)).toBe(true)
  })

  it('is empty for anything that is not a link', () => {
    expect(claimsVsReality({ ...maliciousUrl, analysis: {} }, 'MALICIOUS')).toEqual([])
  })
})

describe('linkXray', () => {
  it('splits the link into scheme, decoration, owner and path', () => {
    const parts = linkXray(lookalike)
    expect(parts.map((p) => [p.kind, p.text])).toEqual([
      ['scheme', 'https://'],
      ['subdomain', 'sbi.co.in.'],
      ['owner', 'kyc-verify.xyz'],
      ['path', '/login'],
    ])
    expect(xrayNotes(lookalike, parts, 'MALICIOUS').map((n) => n.title)).toEqual(['HTTPS', 'Decoration', 'Who owns it', 'Wording'])
  })

  it('marks digits posing as letters and non-Latin characters', () => {
    expect(lookalikeIndices('nati0nal')).toEqual([4])
    expect(lookalikeIndices('bank24')).toEqual([])
    expect(lookalikeIndices('pаypal')).toEqual([1]) // Cyrillic а
  })
})

describe('scoreBreakdown', () => {
  it('lists the points per sign, the floor, and totals to the risk score', () => {
    const floored: AnalysisResult = {
      ...maliciousUrl,
      score_breakdown: { final_score: 73, floor_applied: { indicator: 'URL_NO_HTTPS', minimum_score: 73, points_added: 25 } },
    }
    const { rows, total } = scoreBreakdown(floored)
    expect(rows).toEqual([
      { label: 'Real brand address used as a disguise (<img src=x onerror=alert(1)>)', points: 40 },
      { label: 'No secure connection (http://)', points: 8 },
      { label: 'Minimum score for “No secure connection”', points: 25 },
    ])
    expect(total).toBe(73)
  })
})

describe('redirectChain', () => {
  it('shows the steps the server followed, without duplicates', () => {
    const followed: AnalysisResult = {
      ...maliciousUrl,
      analysis: {
        redirects: {
          checked: true,
          final_url: 'https://evil.example/kyc',
          hops: [
            { url: 'https://bit.ly/abc', status_code: 301 },
            { url: 'https://evil.example/kyc', status_code: 200 },
          ],
        },
      },
    }
    expect(redirectChain(followed)).toEqual(['bit.ly/abc', 'evil.example/kyc'])
    expect(redirectChain(maliciousUrl)).toEqual([])
  })
})
