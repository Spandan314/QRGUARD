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

  it('explains that SAFE + UNVERIFIED is not a guarantee', () => {
    render(<ResultCard result={safeUnverified} />)
    const verification = screen.getByTestId('verification')
    expect(verification).toHaveTextContent('Unverified')
    expect(verification).toHaveTextContent('not a guarantee')
    expect(screen.getByText('No warning signs were found.')).toBeInTheDocument()
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
    expect(screen.getByText('http://sbi.co.in.kyc-verify.xyz/login').tagName).toBe('SPAN')
  })

  it('shows provider problems honestly', () => {
    render(<ResultCard result={maliciousUrl} />)
    expect(screen.getByText('Could not be checked (timeout)')).toBeInTheDocument()
    expect(screen.getByText('Not enabled')).toBeInTheDocument()
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
