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

  it('says SAFE + UNVERIFIED is not a guarantee', async () => {
    await render(<ResultView result={safeUnverified} />)
    expect(screen.getByTestId('verification')).toHaveTextContent(/not a guarantee/)
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

  it('asks before opening a SAFE link and opens only after confirmation', async () => {
    const alert = jest.spyOn(Alert, 'alert').mockImplementation(() => undefined)
    const open = jest.spyOn(Linking, 'openURL').mockResolvedValue(true)
    await render(<ResultView result={{ ...safeUnverified, analysis: { normalized_url: 'https://www.sbi.co.in/' } }} />)
    await press('Open link')
    expect(open).not.toHaveBeenCalled()
    const buttons = alert.mock.calls[0]?.[2] ?? []
    expect(alert.mock.calls[0]?.[1]).toBe('https://www.sbi.co.in/')
    buttons.find((b) => b.text === 'Open')?.onPress?.()
    expect(open).toHaveBeenCalledWith('https://www.sbi.co.in/')
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
