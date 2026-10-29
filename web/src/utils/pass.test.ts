import { maliciousUrl, qrResult, safeUnverified, screenshotResult } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { STAMP, defang, passData, passNumber } from './pass'

const at = new Date(2026, 9, 28, 19, 4)

describe('inspection pass', () => {
  it('stamps each verdict, and never stamps NOT VERIFIED as safe', () => {
    expect(STAMP).toEqual({ MALICIOUS: 'DANGER', SUSPICIOUS: 'CAUTION', SAFE: 'SAFE', UNVERIFIED: 'NOT VERIFIED' })
    expect(passData(safeUnverified, at).stamp).toBe('NOT VERIFIED')
  })

  it('numbers the pass from the request ID', () => {
    expect(passNumber('5f3c9a12-7b44-4e0d')).toBe('QG-5F3C9A12')
    expect(passNumber('')).toBe('QG-00000000')
  })

  it('shows what the link claims, what it is, the strongest sign and when it was checked', () => {
    const fake: AnalysisResult = {
      ...maliciousUrl,
      analysis: { ...maliciousUrl.analysis, host: 'sbi.co.in.kyc-verify.xyz', domain: 'kyc-verify.xyz', brand: { brand: 'State Bank of India', match_type: 'impersonation' } },
    }
    const pass = passData(fake, at)
    expect(pass.title).toBe('sbi.co.in.kyc-verify.xyz')
    expect(pass.fields).toEqual([
      { label: 'SAYS IT IS', value: 'State Bank of India' },
      { label: 'REALLY IS', value: 'A website on kyc-verify.xyz' },
      { label: 'MAIN FINDING', value: 'Real brand address used as a disguise' },
      { label: 'CHECKED ON', value: '28 Oct · 19:04' },
    ])
  })

  it('never puts a clickable link in the shared text', () => {
    const fake = { ...maliciousUrl, analysis: { ...maliciousUrl.analysis, host: 'evil.example.xyz' } }
    const text = passData(fake, at).shareText
    expect(text).toContain('evil[.]example[.]xyz')
    expect(text).not.toMatch(/https?:|evil\.example/)
    expect(defang('a.b')).toBe('a[.]b')
  })

  it('names a UPI QR by its payee and leaves out facts that are missing', () => {
    const pass = passData(qrResult, at)
    expect(pass.title).toBe('UPI QR · refund.desk9912@okdemo')
    expect(pass.fields.map((f) => f.label)).toEqual(['MAIN FINDING', 'CHECKED ON']) // no payee name: no SAYS IT IS / REALLY IS
    expect(passData(screenshotResult, at).title).toBe('A screenshot')
    expect(passData(safeUnverified, at).fields[0]).toEqual({ label: 'MAIN FINDING', value: 'No warning signs, not confirmed' })
  })
})
