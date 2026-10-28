import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { maliciousUrl, safeUnverified } from '../test/fixtures'
import type { AnalysisResult } from '../types/api'
import { ResultCard } from './ResultCard'

afterEach(() => vi.restoreAllMocks())

function urlResult(inputUrl: string, normalized: string, base: AnalysisResult = safeUnverified): AnalysisResult {
  return { ...base, input_type: 'url', analysis: { input_url: inputUrl, normalized_url: normalized } }
}

/** The confirm control: a real link the user clicks (never a scripted window.open popup). */
function confirmLink(host: string): HTMLAnchorElement {
  return screen.getByRole('link', { name: `Open ${host} in a new tab` }) as HTMLAnchorElement
}

/** jsdom cannot open tabs: stop the link's default navigation but keep React's click handler. */
function preventNavigation() {
  const stop = (event: Event) => event.preventDefault()
  document.addEventListener('click', stop)
  return () => document.removeEventListener('click', stop)
}

describe('Open checked link', () => {
  it.each([
    ['offer.com', 'https://offer.com/'],
    ['https://offer.com', 'https://offer.com/'],
    ['OFFER.COM/Deals', 'https://offer.com/Deals'],
  ])('typed %s: opens exactly the analysed %s, only after confirmation', async (typed, normalized) => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<ResultCard result={urlResult(typed, normalized)} />)
    expect(screen.queryByRole('link', { name: /in a new tab/ })).toBeNull() // nothing to follow yet
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    const dialog = screen.getByTestId('open-link-confirm')
    expect(dialog).toHaveTextContent('You are about to open offer.com')
    expect(dialog).toHaveTextContent('QRGUARD could not verify this website') // UNVERIFIED caution
    const link = confirmLink('offer.com')
    expect(link.getAttribute('href')).toBe(normalized) // exactly the checked URL, unchanged
    expect(link).toHaveAttribute('target', '_blank')
    expect(link.rel.split(' ')).toEqual(expect.arrayContaining(['noopener', 'noreferrer']))
    expect(link).toHaveAttribute('referrerpolicy', 'no-referrer')
    expect(open).not.toHaveBeenCalled() // no scripted popup that a blocker could swallow
  })

  it('opens in a new tab when confirmed and then closes the confirmation', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    const followed: string[] = []
    const record = (event: MouseEvent) => {
      const anchor = (event.target as Element).closest('a')
      if (anchor) followed.push(`${anchor.getAttribute('href')} -> ${anchor.target}`)
      event.preventDefault()
    }
    document.addEventListener('click', record)
    try {
      render(<ResultCard result={urlResult('offer.com', 'https://offer.com/')} />)
      await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
      await userEvent.click(confirmLink('offer.com'))
      expect(followed).toEqual(['https://offer.com/ -> _blank'])
      await waitFor(() => expect(screen.queryByTestId('open-link-confirm')).toBeNull())
      expect(open).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('click', record)
    }
  })

  it('keeps working when the browser refuses scripted popups', async () => {
    // A popup blocker, extension or in-app browser that makes window.open do nothing: the old
    // implementation silently closed the dialog without opening anything.
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    const restore = preventNavigation()
    try {
      render(<ResultCard result={urlResult('offer.com', 'https://offer.com/')} />)
      await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
      const link = confirmLink('offer.com')
      await userEvent.click(link)
      expect(link.getAttribute('href')).toBe('https://offer.com/')
      expect(open).not.toHaveBeenCalled()
    } finally {
      restore()
    }
  })

  it('never substitutes the redirect destination, but shows it before opening', async () => {
    const result = urlResult('offer.com', 'https://offer.com/')
    result.analysis.redirects = { checked: true, status: 'completed', final_url: 'https://www.offers.com/' }
    render(<ResultCard result={result} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    expect(screen.getByTestId('open-link-confirm')).toHaveTextContent('This link redirects to: https://www.offers.com/')
    expect(confirmLink('offer.com').getAttribute('href')).toBe('https://offer.com/')
  })

  it('can be cancelled', async () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null)
    render(<ResultCard result={urlResult('offer.com', 'https://offer.com/')} />)
    await userEvent.click(screen.getByRole('button', { name: 'Open checked link' }))
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByTestId('open-link-confirm')).toBeNull()
    expect(screen.queryByRole('link', { name: /in a new tab/ })).toBeNull()
    expect(open).not.toHaveBeenCalled()
  })

  it.each(['SUSPICIOUS', 'MALICIOUS'] as const)('a %s link can only be copied, never opened', (level) => {
    const base = urlResult('https://amaz0n-offers.example/deal', 'https://amaz0n-offers.example/deal', maliciousUrl)
    render(<ResultCard result={{ ...base, risk_level: level, verdict: undefined }} />)
    expect(screen.getByRole('button', { name: 'Copy link' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Open checked link/ })).toBeNull()
    expect(screen.queryByRole('link', { name: /in a new tab/ })).toBeNull()
    expect(screen.getByTestId('never-open-reason')).toHaveTextContent('does not offer to open links it found suspicious')
  })

  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'intent://scan/#Intent;scheme=zxing;end',
    'file:///etc/passwd',
    'https://exa mple.com/',
    'https://example.com/\u0000',
    'ftp://example.com/file',
  ])('never offers to open the invalid or non-web URL %s', (bad) => {
    render(<ResultCard result={urlResult(bad, bad)} />)
    expect(screen.queryByRole('button', { name: /Open checked link/ })).toBeNull()
    expect(screen.queryByRole('link', { name: /in a new tab/ })).toBeNull()
    expect(screen.getByTestId('never-open-reason')).toHaveTextContent('not a normal web link')
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
