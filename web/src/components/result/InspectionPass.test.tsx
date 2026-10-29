import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { maliciousUrl, safeUnverified } from '../../test/fixtures'
import { InspectionPass } from './InspectionPass'

function setShare(share: ((data: ShareData) => Promise<void>) | undefined) {
  Object.defineProperty(navigator, 'share', { value: share, configurable: true, writable: true })
}

afterEach(() => {
  setShare(undefined)
  vi.restoreAllMocks()
})

describe('InspectionPass', () => {
  it('shows the ticket with the stamp, the pass number and no link', () => {
    render(<InspectionPass result={maliciousUrl} />)
    expect(screen.getByRole('img', { name: 'Result stamp: danger' })).toHaveTextContent('DANGER')
    expect(screen.getByTestId('pass-number')).toHaveTextContent('CHECK NO. QG-REQ123')
    expect(screen.getByTestId('pass-ticket').querySelector('a')).toBeNull()
    expect(screen.getByTestId('pass-ticket')).not.toHaveTextContent(/confirm|scan this/i)
  })

  it('stamps a not verified result NOT VERIFIED, never SAFE', () => {
    render(<InspectionPass result={safeUnverified} />)
    expect(screen.getByTestId('pass-stamp')).toHaveTextContent('NOT VERIFIED')
  })

  it('shares with the Web Share API when there is one', async () => {
    const share = vi.fn(async () => {})
    setShare(share)
    render(<InspectionPass result={maliciousUrl} />)
    await userEvent.click(screen.getByRole('button', { name: 'Share the card' }))
    expect(share).toHaveBeenCalledWith(expect.objectContaining({ title: 'QRGUARD check QG-REQ123', text: expect.stringContaining('DANGER') }))
    expect(screen.getByTestId('pass-status')).toHaveTextContent('Shared.')
  })

  it('copies the text when the browser cannot share, and does nothing when the user cancels', async () => {
    const user = userEvent.setup()
    render(<InspectionPass result={maliciousUrl} />)
    await user.click(screen.getByRole('button', { name: 'Share the card' }))
    expect(await navigator.clipboard.readText()).toMatch(/^QRGUARD check QG-REQ123: DANGER\./)
    expect(screen.getByTestId('pass-status')).toHaveTextContent('Copied')

    setShare(vi.fn(async () => Promise.reject(new DOMException('cancelled', 'AbortError'))))
    await user.click(screen.getByRole('button', { name: 'Share the card' }))
    expect(screen.getByTestId('pass-status')).toHaveTextContent('Copied') // unchanged
  })

  it('says so when the image cannot be drawn', async () => {
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(null)
    render(<InspectionPass result={maliciousUrl} />)
    await userEvent.click(screen.getByRole('button', { name: 'Save as image' }))
    expect(await screen.findByText('Could not create the image in this browser.')).toBeInTheDocument()
  })
})
