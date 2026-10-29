import { maliciousUrl, qrResult, safeUnverified, screenshotResult, tiListed } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { chamberLog, detectInput, finalDestination, finishedStages, idleStages, runningStages, upiPayload } from './airlock'

describe('detectInput', () => {
  it.each([
    ['https://example.com/a', 'link'],
    ['example.com', 'link'],
    ['www.sbi.co.in/login?x=1', 'link'],
    ['bit.ly/abc', 'link'],
    ['upi://pay?pa=shop@okaxis', 'link'],
    ['javascript:alert(1)', 'link'], // the server reports dangerous schemes
    ['refund.desk9912@okdemo', 'upi'],
    ['name.surname@ybl', 'upi'],
    ['someone@gmail.com', 'message'], // an e-mail address is not a UPI ID
    ['Your account is blocked, update KYC at http://x.xyz', 'message'],
    ['hello', 'message'],
    ['   ', null],
  ])('%s -> %s', (input, expected) => {
    expect(detectInput(input)).toBe(expected)
  })

  it('turns a UPI ID into the payment payload a QR code would carry', () => {
    expect(upiPayload(' shop@okaxis ')).toBe('upi://pay?pa=shop%40okaxis')
  })
})

describe('stages', () => {
  it('idle and running stages never claim results that do not exist yet', () => {
    expect(idleStages().every((s) => s.state === 'waiting')).toBe(true)
    const running = runningStages()
    expect(running.map((s) => s.state)).toEqual(['active', 'active', 'active', 'active', 'waiting'])
    expect(running.map((s) => s.label)).toEqual(['Read it', 'Followed the link', 'Warning signs', 'Scam databases', 'Result'])
  })

  it('reports warning signs, provider failures and the verdict from the real result', () => {
    const stages = finishedStages(maliciousUrl, 'MALICIOUS')
    expect(stages.map((s) => [s.id, s.state, s.detail])).toEqual([
      ['decoded', 'done', 'link read'],
      ['unshortened', 'done', 'no links'],
      ['inspected', 'warning', '2 found'],
      ['threats', 'warning', '1 did not answer'], // a timeout is never shown as a clean lookup
      ['verdict', 'warning', 'malicious'],
    ])
  })

  it('shows a listing as flagged, and an unverified clean result as not verified', () => {
    const realListing = { ...tiListed, threat_intel: { ...tiListed.threat_intel, providers: [{ provider: 'urlhaus', status: 'listed' as const }] } }
    expect(finishedStages(realListing, 'MALICIOUS')[3]).toMatchObject({ state: 'warning', detail: 'on 1 scam list' })
    expect(finishedStages(safeUnverified, 'UNVERIFIED')[4]).toMatchObject({ state: 'done', detail: 'not verified' })
  })

  it('describes redirects followed on the server and links that were not short links', () => {
    const followed: AnalysisResult = {
      ...maliciousUrl,
      checks: [{ id: 'destination', label: 'Where the link leads', status: 'completed', detail: null }],
      analysis: { ...maliciousUrl.analysis, redirects: { checked: true, redirect_count: 2, final_url: 'https://evil.example/kyc' } },
    }
    expect(finishedStages(followed, 'MALICIOUS')[1]).toMatchObject({ state: 'done', detail: 'sent on to 2 other pages' })
    expect(finalDestination(followed)).toBe('https://evil.example/kyc')
    const notShort = { ...maliciousUrl, checks: [{ id: 'destination', label: 'x', status: 'not_run' as const, detail: null }] }
    expect(finishedStages(notShort, 'MALICIOUS')[1]).toMatchObject({ state: 'done', detail: 'not a short link, no need' })
    expect(finalDestination(maliciousUrl)).toBeNull()
  })

  it('names how the input was read', () => {
    expect(finishedStages(qrResult, 'SUSPICIOUS')[0]?.detail).toMatch(/^QR code/)
    expect(finishedStages(screenshotResult, 'MALICIOUS')[0]?.detail).toMatch(/text/)
  })
})

describe('chamberLog', () => {
  it('lists warning signs, provider outcomes and the verdict, and never calls a failure clean', () => {
    const lines = chamberLog(maliciousUrl, 'MALICIOUS').map((l) => `${l.tone}|${l.text}`)
    expect(lines.at(-1)).toBe('danger|result: MALICIOUS · risk 73 out of 100')
    expect(lines.some((l) => l.startsWith('warn|virustotal: too slow to answer – not checked'))).toBe(true)
    expect(lines.some((l) => l.endsWith('1 scam database not set up'))).toBe(true)
    expect(lines.filter((l) => /^(warn|danger)\|/.test(l)).length).toBeGreaterThanOrEqual(3)
  })

  it('says NOT VERIFIED rather than UNVERIFIED', () => {
    expect(chamberLog(safeUnverified, 'UNVERIFIED').at(-1)?.text).toBe('result: NOT VERIFIED · risk 0 out of 100')
  })
})

describe('providers looked up twice (short link and its destination)', () => {
  it('count once per provider and keep the most serious answer', () => {
    const twice: AnalysisResult = {
      ...maliciousUrl,
      threat_intel: {
        checked: true,
        note: 'n',
        providers: [
          { provider: 'urlhaus', status: 'not_listed' },
          { provider: 'virustotal', status: 'not_listed' },
          { provider: 'urlhaus', status: 'listed' }, // the destination is listed
          { provider: 'virustotal', status: 'unavailable', detail: 'timeout' },
        ],
      },
    }
    expect(finishedStages(twice, 'MALICIOUS')[3]).toMatchObject({ state: 'warning', detail: 'on 1 scam list' })
    const log = chamberLog(twice, 'MALICIOUS').map((l) => l.text)
    expect(log.filter((t) => t.startsWith('urlhaus:'))).toEqual(['urlhaus: listed as dangerous'])
    expect(log.filter((t) => t.startsWith('virustotal:'))).toEqual(['virustotal: too slow to answer – not checked'])
  })
})

describe('demo data is never shown as threat intelligence', () => {
  it('a hit on the demo blocklist alone says "on our test list only"', () => {
    const demo: AnalysisResult = {
      ...maliciousUrl,
      threat_intel: { checked: true, note: 'n', providers: [{ provider: 'local_feed', status: 'listed', limited_coverage: true }] },
      indicators: [
        { id: 'TI_DEMO_LISTED', severity: 'critical', title: "On QRGUARD's demo blocklist (demonstration data)", message: 'm', evidence: 'QRGUARD demo blocklist (demonstration data)', weight: 100, score_contribution: 90, module: 'threat_intel' },
      ],
    }
    expect(finishedStages(demo, 'MALICIOUS')[3]).toMatchObject({ state: 'warning', detail: 'on our test list only' })
    // evidence that only repeats the title is not repeated in the log
    expect(chamberLog(demo, 'MALICIOUS')).toContainEqual({ text: "on qrguard's demo blocklist (demonstration data)", tone: 'danger' })
  })
})
