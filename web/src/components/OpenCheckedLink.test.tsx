import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { maliciousUrl, safeUnverified } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { ResultCard } from './ResultCard'

afterEach(() => vi.restoreAllMocks())

function urlResult(inputUrl: string, normalized: string, base: AnalysisResult = safeUnverified): AnalysisResult {
  return { ...base, input_type: 'url', analysis: { input_url: inputUrl, normalized_url: normalized } }
}

describe('Open checked link', () => {
  it.each([
    ['offer.com', 'https://offer.com/'],
    ['https://offer.com', 'https://offer.com/'],
    ['OFFER.COM/Deals', 'https://offer.com/Deals'],
  ])('typed %s: opens exactly the analysed %s, only after confirmation', async (typed, normalized) => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<ResultCard result={urlResult(typed, normalized)} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    expect(open).not.toHaveBeenCalled() // never opened automatically
    const dialog = screen.getByTestId('open-link-confirm')
    expect(dialog).toHaveTextContent('You are about to open offer.com')
    expect(dialog).toHaveTextContent('QRGUARD could not verify this website') // UNVERIFIED caution
    await userEvent.click(screen.getByRole('button', { name: 'Open offer.com in a new tab' }))
    expect(open).toHaveBeenCalledTimes(1)
    expect(open).toHaveBeenCalledWith(normalized, '_blank', 'noopener,noreferrer')
  })

  it('never substitutes the redirect destination, but shows it before opening', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    const result = urlResult('offer.com', 'https://offer.com/')
    result.analysis.redirects = { checked: true, status: 'completed', final_url: 'https://www.offers.com/' }
    render(<ResultCard result={result} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    expect(screen.getByTestId('open-link-confirm')).toHaveTextContent('This link redirects to: https://www.offers.com/')
    await userEvent.click(screen.getByRole('button', { name: 'Open offer.com in a new tab' }))
    expect(open).toHaveBeenCalledWith('https://offer.com/', '_blank', 'noopener,noreferrer')
  })

  it('can be cancelled', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<ResultCard result={urlResult('offer.com', 'https://offer.com/')} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByTestId('open-link-confirm')).toBeNull()
    expect(open).not.toHaveBeenCalled()
  })

  it('needs an explicit acknowledgement for a MALICIOUS link', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<ResultCard result={urlResult('https://amaz0n-offers.example/deal', 'https://amaz0n-offers.example/deal', maliciousUrl)} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link (not recommended)' }))
    const confirm = screen.getByRole('button', { name: 'Open amaz0n-offers.example in a new tab' })
    expect(confirm).toBeDisabled()
    await userEvent.click(screen.getByLabelText('I understand this link is very likely dangerous'))
    await userEvent.click(confirm)
    expect(open).toHaveBeenCalledWith('https://amaz0n-offers.example/deal', '_blank', 'noopener,noreferrer')
  })

  it('never offers to open a user@host disguise or a non-web link', () => {
    render(<ResultCard result={urlResult('x', 'https://paypal.com@evil.example/login', maliciousUrl)} />)
    expect(screen.queryByRole('button', { name: /Open checked link/ })).toBeNull()
    expect(screen.getByTestId('never-open-reason')).toHaveTextContent('common trick')
  })

  it('shows no open action for a message without a checked link', () => {
    render(<ResultCard result={{ ...safeUnverified, input_type: 'message', analysis: {} }} />)
    expect(screen.queryByTestId('open-checked-link')).toBeNull()
  })
})
