import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals'
import { fireEvent, render, screen } from '@testing-library/react-native'
import { Alert, Linking } from 'react-native'
import { maliciousUrl, qrResult, safeUnverified, screenshotResult, tiListed } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { ResultView } from './ResultView'

describe('ResultView', () => {
  it('shows level, score, summary and recommendation', async () => {
    await render(<ResultView result={maliciousUrl} />)
    expect(screen.getAllByTestId('risk-badge')[0]).toHaveTextContent('⛔ MALICIOUS')
    expect(screen.getByTestId('score-gauge')).toHaveAccessibilityValue({ now: 73 })
    expect(screen.getByText(maliciousUrl.summary)).toBeOnTheScreen()
    expect(screen.getByText(/report financial fraud at 1930/)).toBeOnTheScreen()
    expect(screen.getByText('Phishing · Impersonation scam')).toBeOnTheScreen()
  })

  it('orders indicators by severity with their points', async () => {
    await render(<ResultView result={maliciousUrl} />)
    const items = screen.getAllByTestId('indicator')
    expect(items[0]).toHaveTextContent(/Real brand address used as a disguise/)
    expect(items[0]).toHaveTextContent(/\+40 pts/)
  })

  it('never shows an unverified site as SAFE', async () => {
    await render(<ResultView result={safeUnverified} />)
    expect(screen.getAllByTestId('risk-badge')[0]).toHaveTextContent('❔ NOT VERIFIED')
    expect(screen.queryByText(/✅ SAFE/)).toBeNull()
    expect(screen.getByTestId('verdict-title')).toHaveTextContent('Not verified – no known risks found')
  })

  it("uses the backend's verdict and lists the checks behind it", async () => {
    await render(
      <ResultView
        result={{
          ...safeUnverified,
          verdict: { label: 'UNVERIFIED', confirmed: false, title: 'Not verified – no known risks found', explanation: 'x' },
          checks: [
            { id: 'url_structure', label: 'Link structure and look-alike domains', status: 'completed', detail: null },
            { id: 'destination', label: 'Where the link leads (redirects)', status: 'completed', detail: 'leads to another website: offers.com' },
            { id: 'threat_intelligence', label: 'Threat-intelligence databases', status: 'limited', detail: "only QRGUARD's small demo blocklist" },
          ],
          analysis: { normalized_url: 'https://offer.com/', redirects: { checked: true, status: 'completed', final_url: 'https://www.offers.com/' } },
        }}
      />,
    )
    expect(screen.getByTestId('check-threat_intelligence')).toHaveTextContent(/◐ Threat-intelligence databases: limited/)
    expect(screen.getByTestId('check-destination')).toHaveTextContent(/leads to another website: offers.com/)
    expect(screen.getByTestId('final-url')).toHaveTextContent('https://www.offers.com/')
  })

  it('shows SAFE only for a recognised website', async () => {
    await render(
      <ResultView
        result={{
          ...safeUnverified,
          verification: { status: 'VERIFIED', source: 'trusted_domain_list', message: 'Recognised.' },
        }}
      />,
    )
    expect(screen.getAllByTestId('risk-badge')[0]).toHaveTextContent('✅ SAFE')
  })

  it('shows threat-intelligence verification and provider status', async () => {
    await render(<ResultView result={tiListed} />)
    expect(screen.getByTestId('verification')).toHaveTextContent(/Verified by threat intelligence/)
    expect(screen.getByText(/Local blocklist: Listed as malicious · demo list only/)).toBeOnTheScreen()
  })

  it('shows OCR text and links for screenshots, without an open button', async () => {
    await render(<ResultView result={screenshotResult} />)
    expect(screen.getByTestId('ocr-text')).toHaveTextContent(/BLOCKED/)
    expect(screen.getByText(/http:\/\/sbi-kyc-update.xyz\/login/)).toBeOnTheScreen()
    expect(screen.queryByTestId('open-link-guard')).toBeNull()
  })

  it('warns that scanning a UPI QR sends money', async () => {
    await render(<ResultView result={qrResult} />)
    expect(screen.getByTestId('qr-content')).toHaveTextContent(/refund.desk9912@okdemo/)
    expect(screen.getByText(/always sends money/)).toBeOnTheScreen()
  })

  it('never offers to open a dangerous-scheme QR code', async () => {
    const result: AnalysisResult = {
      ...qrResult,
      analysis: { qr: { source: 'camera', codes_found: 1, decoded_content: 'intent://x#Intent;end', content_type: 'url', parsed: {} } },
    }
    await render(<ResultView result={result} />)
    expect(screen.getByTestId('open-link-guard')).toBeOnTheScreen()
    expect(screen.queryByText('Open link')).toBeNull()
    expect(screen.queryByText('Open link (not recommended)')).toBeNull()
  })
})

describe('OpenLinkGuard', () => {
  // Linking.openURL is already a jest.fn in jest-expo, so spyOn reuses it: clear recorded calls.
  beforeEach(() => {
    jest.clearAllMocks()
  })
  afterEach(() => {
    jest.restoreAllMocks()
  })

  async function press(label: string) {
    await fireEvent.press(screen.getByText(label))
  }

  it('asks before opening a recognised link and opens exactly that URL after confirmation', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    const open = jest.spyOn(Linking, 'openURL').mockResolvedValue(true)
    const verified = { status: 'VERIFIED' as const, source: 'trusted_domain_list' as const, message: 'Recognised.' }
    await render(<ResultView result={{ ...safeUnverified, verification: verified, analysis: { normalized_url: 'https://www.sbi.co.in/' } }} />)
    await press('Open link')
    expect(open).not.toHaveBeenCalled()
    expect(alert.mock.calls[0]?.[0]).toBe('Open this link?')
    expect(alert.mock.calls[0]?.[1]).toBe('You are about to open www.sbi.co.in:\nhttps://www.sbi.co.in/')
    alert.mock.calls[0]?.[2]?.find((b) => b.text === 'Open')?.onPress?.()
    expect(open).toHaveBeenCalledWith('https://www.sbi.co.in/')
  })

  it('opens offer.com as offer.com, with a caution and the redirect it leads to', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    const open = jest.spyOn(Linking, 'openURL').mockResolvedValue(true)
    await render(
      <ResultView
        result={{
          ...safeUnverified,
          analysis: { normalized_url: 'https://offer.com/', redirects: { checked: true, status: 'completed', final_url: 'https://www.offers.com/' } },
        }}
      />,
    )
    await press('Open link')
    expect(alert.mock.calls[0]?.[0]).toBe('Open an unverified link?')
    const message = String(alert.mock.calls[0]?.[1])
    expect(message).toContain('You are about to open offer.com:\nhttps://offer.com/')
    expect(message).toContain('This link redirects to:\nhttps://www.offers.com/')
    alert.mock.calls[0]?.[2]?.find((b) => b.text === 'Open')?.onPress?.()
    expect(open).toHaveBeenCalledWith('https://offer.com/')
    expect(open).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['offer.com', 'https://offer.com/'],
    ['https://offer.com', 'https://offer.com/'],
    ['OFFER.COM/Deals', 'https://offer.com/Deals'],
  ])('typed %s: opens exactly the analysed %s and only after confirmation', async (typed, normalized) => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    const open = jest.spyOn(Linking, 'openURL').mockResolvedValue(true)
    await render(<ResultView result={{ ...safeUnverified, analysis: { input_url: typed, normalized_url: normalized } }} />)
    await press('Open link')
    expect(open).not.toHaveBeenCalled()
    expect(String(alert.mock.calls[0]?.[1])).toContain(`You are about to open offer.com:\n${normalized}`)
    alert.mock.calls[0]?.[2]?.find((b) => b.text === 'Open')?.onPress?.()
    expect(open).toHaveBeenCalledWith(normalized)
  })

  it('never opens a link that hides its host behind "@"', async () => {
    await render(<ResultView result={{ ...maliciousUrl, analysis: { normalized_url: 'https://paypal.com@evil.example/login' } }} />)
    expect(screen.queryByText(/Open link/)).toBeNull()
    expect(screen.getByTestId('never-open-reason')).toHaveTextContent(/common trick/)
  })

  it('needs two confirmations for a MALICIOUS link', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    const open = jest.spyOn(Linking, 'openURL').mockResolvedValue(true)
    await render(<ResultView result={maliciousUrl} />)
    await press('Open link (not recommended)')
    alert.mock.calls[0]?.[2]?.find((b) => b.text === 'I understand the risk')?.onPress?.()
    expect(open).not.toHaveBeenCalled()
    expect(alert.mock.calls[1]?.[0]).toBe('Are you absolutely sure?')
    alert.mock.calls[1]?.[2]?.find((b) => b.text === 'Open')?.onPress?.()
    expect(open).toHaveBeenCalledTimes(1)
  })

  it('warns before opening a SUSPICIOUS link', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    await render(<ResultView result={{ ...maliciousUrl, risk_level: 'SUSPICIOUS', risk_score: 40 }} />)
    await press('Open link')
    expect(alert.mock.calls[0]?.[0]).toBe('This link looks suspicious')
  })

  it('copies the link', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    await render(<ResultView result={maliciousUrl} />)
    await press('Copy link')
    await screen.findByTestId('open-link-guard')
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(alert).toHaveBeenCalledWith('Copied', expect.any(String))
  })
})

describe('ResultView verification note', () => {
  const CAVEAT = 'There is insufficient evidence to establish trust. A SAFE result does not guarantee that the website is safe.'
  const unconfirmed = { status: 'UNVERIFIED' as const, source: null, message: CAVEAT }
  const note = () => screen.getByTestId('verification')
  // toHaveTextContent matches a whole string exactly; these checks look for a part of the note.
  const part = (text: string) => new RegExp(text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))

  it.each(['MALICIOUS', 'SUSPICIOUS'] as const)('%s without confirmation says so, without the SAFE caveat', async (level) => {
    await render(<ResultView result={{ ...maliciousUrl, risk_level: level, verification: unconfirmed }} />)
    expect(note()).toHaveTextContent(part('Not confirmed by a threat-intelligence source.'))
    expect(note()).not.toHaveTextContent(/Verified|SAFE result/)
    expect(screen.queryByText(/A SAFE result does not guarantee/)).toBeNull()
  })

  it('keeps the demo-blocklist note under a warning, still not confirmed', async () => {
    const demo = 'Listed only on QRGUARD\'s demo blocklist (demonstration data). No real threat-intelligence source has confirmed it.'
    await render(
      <ResultView
        result={{
          ...maliciousUrl,
          verification: { ...unconfirmed, message: demo },
          verdict: { label: 'MALICIOUS', confirmed: false, evidence: 'demo_blocklist', title: 'Malicious – on QRGUARD\'s demo blocklist', explanation: demo },
        }}
      />,
    )
    expect(note()).toHaveTextContent(part('Not confirmed by a threat-intelligence source.'))
    expect(note()).toHaveTextContent(part(demo))
  })

  it('a warning confirmed by threat intelligence still says so', async () => {
    await render(<ResultView result={tiListed} />)
    expect(note()).toHaveTextContent(part('Verified by threat intelligence'))
    expect(note()).not.toHaveTextContent(part('Not confirmed'))
  })

  it('UNVERIFIED keeps the backend message, caveat included', async () => {
    await render(<ResultView result={{ ...safeUnverified, verification: unconfirmed }} />)
    expect(note()).toHaveTextContent(part('Unverified'))
    expect(note()).toHaveTextContent(part(CAVEAT))
    expect(note()).not.toHaveTextContent(part('Not confirmed'))
  })

  it('SAFE keeps the backend message', async () => {
    const verification = { status: 'VERIFIED' as const, source: 'trusted_domain_list' as const, message: 'Recognised.' }
    await render(<ResultView result={{ ...safeUnverified, verification }} />)
    expect(note()).toHaveTextContent(part('Verified – recognised legitimate website'))
    expect(note()).toHaveTextContent(part('Recognised.'))
  })
})

describe('ResultView layout and provider status', () => {
  it('shows "What you should do" right after the verdict banner', async () => {
    await render(<ResultView result={maliciousUrl} />)
    const titles = screen.getAllByText(/^(What you should do|What QRGUARD checked|Why this result|Threat-intelligence checks)$/)
    expect(titles[0]).toHaveTextContent('What you should do')
  })

  it('tells checked, flagged, failed and unconfigured sources apart', async () => {
    const providers = [
      { provider: 'virustotal', status: 'partial' as const, detail: '2/94 engines' },
      { provider: 'phishtank', status: 'not_listed' as const },
      { provider: 'urlhaus', status: 'error' as const, detail: 'auth key rejected' },
      { provider: 'google_safe_browsing', status: 'unavailable' as const, detail: 'rate limited' },
      { provider: 'local_feed', status: 'disabled' as const },
    ]
    await render(<ResultView result={{ ...maliciousUrl, threat_intel: { checked: true, providers, note: 'n' } }} />)
    expect(screen.getByTestId('ti-summary')).toHaveTextContent(
      /^2 of 5 sources checked this link, 2 could not, 1 not configured\. A source that did not check this link says nothing about whether it is safe\.$/,
    )
    expect(screen.getByText(/VirusTotal: Flagged by some sources \(2\/94 engines\)/)).toBeOnTheScreen()
    expect(screen.getByText(/PhishTank: Checked – not listed/)).toBeOnTheScreen()
    expect(screen.getByText(/URLhaus: Key rejected – not checked/)).toBeOnTheScreen()
    expect(screen.getByText(/Google Safe Browsing: Rate limited – not checked/)).toBeOnTheScreen()
    expect(screen.getByText(/Local blocklist: Not configured/)).toBeOnTheScreen()
  })
})
