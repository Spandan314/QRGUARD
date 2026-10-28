import { render, screen, within } from '@testing-library/react'
import { maliciousUrl, qrResult, safeUnverified, screenshotResult, tiListed } from '../test/fixtures'
import { ResultCard } from './ResultCard'

describe('ResultCard', () => {
  it('shows the level with icon, word and score', () => {
    render(<ResultCard result={maliciousUrl} />)
    const badge = screen.getAllByTestId('risk-badge')[0]
    expect(badge).toHaveTextContent('⛔')
    expect(badge).toHaveTextContent('MALICIOUS')
    expect(screen.getByRole('meter', { name: 'Risk score' })).toHaveAttribute('aria-valuenow', '73')
    expect(screen.getByText(maliciousUrl.summary)).toBeInTheDocument()
    expect(screen.getByText('Phishing')).toBeInTheDocument()
    expect(screen.getByText(/report financial fraud at 1930/)).toBeInTheDocument()
  })

  it('never presents an unverified result as SAFE', () => {
    render(<ResultCard result={safeUnverified} />)
    expect(screen.getAllByTestId('risk-badge')[0]).toHaveTextContent('NOT VERIFIED')
    expect(screen.queryByText('SAFE')).toBeNull()
    expect(screen.getByTestId('verdict-title')).toHaveTextContent('Not verified – no known risks found')
    expect(screen.getByTestId('verification')).toHaveTextContent('Unverified')
    expect(screen.getByText('No warning signs were found.')).toBeInTheDocument()
  })

  it('shows SAFE only for a recognised website, and lists the checks behind a verdict', () => {
    render(
      <ResultCard
        result={{
          ...safeUnverified,
          verification: { status: 'VERIFIED', source: 'trusted_domain_list', message: 'Recognised.' },
          checks: [{ id: 'threat_intelligence', label: 'Threat-intelligence databases', status: 'limited', detail: 'demo list' }],
        }}
      />,
    )
    expect(screen.getAllByTestId('risk-badge')[0]).toHaveTextContent('SAFE')
    expect(screen.getByTestId('check-threat_intelligence')).toHaveTextContent('Threat-intelligence databases: limited (demo list)')
  })

  it('shows a threat-intelligence verification', () => {
    render(<ResultCard result={tiListed} />)
    expect(screen.getByTestId('verification')).toHaveTextContent('Verified by threat intelligence')
    expect(screen.getByText(/Listed as malicious · demo list only/)).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Threat intelligence' })).toBeInTheDocument()
  })

  it('orders indicators by severity and shows their points', () => {
    render(<ResultCard result={maliciousUrl} />)
    const items = screen.getAllByTestId('indicator')
    expect(items[0]).toHaveTextContent('Real brand address used as a disguise')
    expect(items[0]).toHaveTextContent('+40 pts')
    expect(items[1]).toHaveTextContent('+8 pts')
  })

  it('never renders data as HTML or as clickable links', () => {
    const { container } = render(<ResultCard result={maliciousUrl} />)
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(container.querySelectorAll('a')).toHaveLength(0)
    // The checked URL appears in the open-link section and the details: always as plain text.
    for (const node of screen.getAllByText('http://sbi.co.in.kyc-verify.xyz/login')) expect(node.tagName).not.toBe('A')
  })

  it('shows provider problems honestly', () => {
    render(<ResultCard result={maliciousUrl} />)
    expect(screen.getByText('Timed out – not checked')).toBeInTheDocument()
    expect(screen.getByText('Not configured')).toBeInTheDocument()
  })

  it('tells checked, flagged, failed and unconfigured sources apart, and never calls a failure clean', () => {
    const providers = [
      { provider: 'google_safe_browsing', status: 'listed' as const, threat_type: 'phishing' },
      { provider: 'virustotal', status: 'partial' as const, detail: '2/94 engines' },
      { provider: 'phishtank', status: 'not_listed' as const },
      { provider: 'urlhaus', status: 'error' as const, detail: 'auth key rejected' },
      { provider: 'local_feed', status: 'unavailable' as const, detail: 'rate limited' },
      { provider: 'other', status: 'unavailable' as const, detail: 'network error' },
      { provider: 'disabled_one', status: 'disabled' as const },
    ]
    render(<ResultCard result={{ ...maliciousUrl, threat_intel: { checked: true, providers, note: 'n' } }} />)
    const outcomes = screen.getAllByTestId('ti-provider').map((row) => [row.textContent, row.dataset.outcome])
    expect(outcomes).toEqual([
      ['Google Safe Browsing⛔ Listed as malicious', 'flagged'],
      ['VirusTotal⛔ Flagged by some sources (2/94 engines)', 'flagged'],
      ['PhishTank✓ Checked – not listed', 'checked'],
      ['URLhaus⚠ Key rejected – not checked', 'not_checked'],
      ['Local blocklist⚠ Rate limited – not checked', 'not_checked'],
      ['other⚠ Unavailable – not checked', 'not_checked'],
      ['disabled_one– Not configured', 'not_configured'],
    ])
    expect(screen.getByTestId('ti-summary')).toHaveTextContent(
      '3 of 7 sources checked this link, 3 could not, 1 not configured. A source that did not check this link says nothing about whether it is safe.',
    )
  })

  it('shows OCR text and found links for screenshots', () => {
    render(<ResultCard result={screenshotResult} />)
    const ocr = screen.getByTestId('ocr-details')
    expect(ocr).toHaveTextContent('Dear customer, your SBI account will be BLOCKED today.')
    expect(ocr).toHaveTextContent('good, 94%')
    expect(screen.getByText('http://sbi-kyc-update.xyz/login')).toBeInTheDocument()
    expect(screen.getByText(/PNG, 1100×210, 21.8 KB/)).toBeInTheDocument()
  })

  it('shows decoded QR content, parsed fields and every code found', () => {
    render(<ResultCard result={qrResult} />)
    const qr = screen.getByTestId('qr-details')
    expect(qr).toHaveTextContent('QR content (upi)')
    expect(within(qr).getByText('payee vpa')).toBeInTheDocument()
    expect(within(qr).getByText('yes')).toBeInTheDocument()
    expect(within(qr).getByText('—')).toBeInTheDocument()
    expect(screen.getByText('(decided the result)')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'QR code content' })).toBeInTheDocument()
  })
})

describe('ResultCard verification note', () => {
  const CAVEAT = 'There is insufficient evidence to establish trust. A SAFE result does not guarantee that the website is safe.'
  const unconfirmed = { status: 'UNVERIFIED' as const, source: null, message: CAVEAT }
  const note = () => screen.getByTestId('verification')

  it.each(['MALICIOUS', 'SUSPICIOUS'] as const)('%s without confirmation says so, without the SAFE caveat', (level) => {
    render(<ResultCard result={{ ...maliciousUrl, risk_level: level, verification: unconfirmed }} />)
    expect(note()).toHaveTextContent('Not confirmed by a threat-intelligence source.')
    expect(note()).not.toHaveTextContent(/Verified|SAFE result/)
    expect(screen.queryByText(/A SAFE result does not guarantee/)).toBeNull()
  })

  it('keeps the demo-blocklist note under a warning, still not confirmed', () => {
    const demo = 'Listed only on QRGUARD\'s demo blocklist (demonstration data). No real threat-intelligence source has confirmed it.'
    render(
      <ResultCard
        result={{
          ...maliciousUrl,
          verification: { ...unconfirmed, message: demo },
          verdict: { label: 'MALICIOUS', confirmed: false, evidence: 'demo_blocklist', title: 'Malicious – on QRGUARD\'s demo blocklist', explanation: demo },
        }}
      />,
    )
    expect(note()).toHaveTextContent('Not confirmed by a threat-intelligence source.')
    expect(note()).toHaveTextContent(demo)
  })

  it('a warning confirmed by threat intelligence still says so', () => {
    render(<ResultCard result={tiListed} />)
    expect(note()).toHaveTextContent('Verified by threat intelligence')
    expect(note()).not.toHaveTextContent('Not confirmed')
  })

  it('UNVERIFIED keeps the backend message, caveat included', () => {
    render(<ResultCard result={{ ...safeUnverified, verification: unconfirmed }} />)
    expect(note()).toHaveTextContent('Unverified')
    expect(note()).toHaveTextContent(CAVEAT)
    expect(note()).not.toHaveTextContent('Not confirmed')
  })

  it('SAFE keeps the backend message', () => {
    const verification = { status: 'VERIFIED' as const, source: 'trusted_domain_list' as const, message: 'Recognised.' }
    render(<ResultCard result={{ ...safeUnverified, verification }} />)
    expect(note()).toHaveTextContent('Verified – recognised legitimate website')
    expect(note()).toHaveTextContent('Recognised.')
  })
})

describe('ResultCard layout', () => {
  it('puts "What you should do" directly under the verdict', () => {
    render(<ResultCard result={maliciousUrl} />)
    const header = screen.getByTestId('verdict-title').closest('header')
    expect(header?.nextElementSibling).toBe(screen.getByTestId('recommendation'))
    expect(screen.getByTestId('recommendation')).toHaveTextContent(maliciousUrl.recommendation)
  })

  it('shows a link from a QR code once in the details, not three times', () => {
    const url = 'https://flipkrat.com/rewards'
    render(
      <ResultCard
        result={{
          ...qrResult,
          analysis: {
            ...qrResult.analysis,
            normalized_url: url,
            qr: { source: 'upload', codes_found: 1, decoded_content: url, content_type: 'url', parsed: { url } },
            qr_codes: undefined,
          },
        }}
      />,
    )
    const details = screen.getByText('Details').closest('details') as HTMLElement
    expect(within(details).getAllByText(url)).toHaveLength(1)
    expect(within(details).queryByText('Checked address:')).toBeNull()
  })
})
