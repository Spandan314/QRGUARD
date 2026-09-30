import { describe, expect, it } from '@jest/globals'
import { isOpenableUrl, linkAction } from './links'

describe('link policy', () => {
  it.each(['https://www.sbi.co.in/', 'http://example.com/path?x=1'])('%s can be opened', (url) => {
    expect(isOpenableUrl(url)).toBe(true)
  })

  it.each([
    'javascript:alert(1)',
    'intent://scan/#Intent;scheme=zxing;end',
    'data:text/html,<script>alert(1)</script>',
    'file:///sdcard/secret',
    'upi://pay?pa=a@b',
    'tel:1930',
    'https://',
    'https://exa mple.com',
  ])('%s is never opened', (url) => {
    expect(isOpenableUrl(url)).toBe(false)
    expect(linkAction(url, 'SAFE')).toBe('never')
  })

  it('gets stricter with the risk level', () => {
    expect(linkAction('https://a.in/', 'SAFE')).toBe('confirm')
    expect(linkAction('https://a.in/', 'SUSPICIOUS')).toBe('warn')
    expect(linkAction('https://a.in/', 'MALICIOUS')).toBe('copy-only')
  })
})
