import { describe, expect, it } from '@jest/globals'
import { hasUserInfo, hostOf, isOpenableUrl, linkAction } from './links'

describe('link policy', () => {
  it.each(['https://www.sbi.co.in/', 'http://example.com/path?x=1', 'https://offer.com/', 'https://xn--pypal-4ve.com/', 'https://shop.example.in:8443/a'])(
    '%s can be opened',
    (url) => {
      expect(isOpenableUrl(url)).toBe(true)
    },
  )

  it.each([
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'intent://scan/#Intent;scheme=zxing;end',
    'data:text/html,<script>alert(1)</script>',
    'file:///sdcard/secret',
    'upi://pay?pa=a@b',
    'tel:1930',
    'https://',
    'https://exa mple.com',
    ' https://offer.com/',
    'https://offer.com/\n',
    'https://paypal.com@evil.example/login',
    'https://user:***@paypal.com.evil.example/',
    'https://-bad-.com/',
  ])('%j is never opened', (url) => {
    expect(isOpenableUrl(url)).toBe(false)
    expect(linkAction(url, 'SAFE')).toBe('never')
  })

  it('gets stricter with the verdict, and an unverified link is never a plain "safe" confirm', () => {
    expect(linkAction('https://a.in/', 'SAFE')).toBe('confirm')
    expect(linkAction('https://a.in/', 'UNVERIFIED')).toBe('caution')
    expect(linkAction('https://a.in/', 'SUSPICIOUS')).toBe('warn')
    expect(linkAction('https://a.in/', 'MALICIOUS')).toBe('copy-only')
  })

  it('names the exact host, so offer.com is never shown as offers.com', () => {
    expect(hostOf('https://offer.com/')).toBe('offer.com')
    expect(hostOf('https://offers.com/deals')).toBe('offers.com')
    expect(hostOf('https://Offer.COM:8443/x')).toBe('offer.com')
    expect(hostOf('https://paypal.com@evil.example/login')).toBe('evil.example')
    expect(hasUserInfo('https://paypal.com@evil.example/login')).toBe(true)
    expect(hasUserInfo('https://offer.com/a@b')).toBe(false)
  })
})
