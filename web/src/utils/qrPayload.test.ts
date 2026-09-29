import { buildPayload, escapeWifi, PayloadError } from './qrPayload'

describe('buildPayload', () => {
  it('keeps text as is', () => {
    expect(buildPayload('text', { text: 'hello' })).toBe('hello')
  })

  it('normalises http(s) links and rejects other schemes', () => {
    expect(buildPayload('url', { url: 'https://Example.com' })).toBe('https://example.com/')
    expect(() => buildPayload('url', { url: 'javascript:alert(1)' })).toThrow(PayloadError)
    expect(() => buildPayload('url', { url: 'example.com' })).toThrow(/http/)
  })

  it('escapes Wi-Fi special characters including backslashes', () => {
    const bs = '\\'
    expect(escapeWifi(`a${bs}b;c,d:e"f`)).toBe(`a${bs}${bs}b${bs};c${bs},d${bs}:e${bs}"f`)
    expect(buildPayload('wifi', { ssid: 'Home;Net', password: `pass${bs}word1`, security: 'WPA' })).toBe(
      `WIFI:T:WPA;S:Home${bs};Net;P:pass${bs}${bs}word1;;`,
    )
  })

  it('supports WPA3, WEP, open and hidden networks', () => {
    expect(buildPayload('wifi', { ssid: 'N', password: '12345678', security: 'WPA3', hidden: true })).toBe(
      'WIFI:T:SAE;S:N;P:12345678;H:true;;',
    )
    expect(buildPayload('wifi', { ssid: 'N', password: 'k', security: 'WEP' })).toBe('WIFI:T:WEP;S:N;P:k;;')
    expect(buildPayload('wifi', { ssid: 'Cafe', security: 'nopass' })).toBe('WIFI:T:nopass;S:Cafe;;')
  })

  it.each([
    [{ ssid: '', password: '12345678' }, /network name/],
    [{ ssid: 'N', password: 'short' }, /8 to 63/],
    [{ ssid: 'N', password: 'x', security: 'nopass' as const }, /open network/],
    [{ ssid: 'N', security: 'WEP' as const }, /WEP/],
  ])('validates Wi-Fi input %#', (input, message) => {
    expect(() => buildPayload('wifi', input)).toThrow(message)
  })

  it('builds mailto links with encoded subject and body', () => {
    expect(buildPayload('email', { to: 'a@b.in', subject: 'Hi there', body: 'x&y' })).toBe(
      'mailto:a@b.in?subject=Hi%20there&body=x%26y',
    )
    expect(buildPayload('email', { to: 'a@b.in' })).toBe('mailto:a@b.in')
    expect(() => buildPayload('email', { to: 'nope' })).toThrow(PayloadError)
    expect(() => buildPayload('email', { to: 'a@b.in', subject: 'x'.repeat(201) })).toThrow(/too long/)
  })

  it('builds tel links', () => {
    expect(buildPayload('phone', { number: '+91 (98) 7654-3210' })).toBe('tel:+919876543210')
    expect(() => buildPayload('phone', { number: 'call me' })).toThrow(PayloadError)
  })

  it('limits text length', () => {
    expect(() => buildPayload('text', { text: '' })).toThrow(PayloadError)
    expect(() => buildPayload('text', { text: 'x'.repeat(1001) })).toThrow(PayloadError)
  })
})
