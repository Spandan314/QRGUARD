// Full-stack E2E: Chromium -> web app (Firebase mode) -> Firebase Auth emulator -> Flask (verifies
// ID tokens) -> analysis + threat intelligence -> Firestore emulator (history). No mocks.
// Run through ../run.sh, which starts everything.
import { execFileSync } from 'node:child_process'
import http from 'node:http'
import { fileURLToPath } from 'node:url'
import { ARTIFACTS, check, finish, launch, watch } from './harness.mjs'
import { chromium } from 'playwright-core'

const WEB = process.env.WEB_URL ?? 'http://localhost:4174'
const BACKEND_DIR = process.env.BACKEND_DIR ?? '../backend'
const PY = process.env.PYTHON ?? 'python'
const AUTH_EMULATOR = process.env.FIREBASE_AUTH_EMULATOR_HOST ?? '127.0.0.1:9099'

const browser = await launch([
  '--use-fake-ui-for-media-stream',
  '--use-fake-device-for-media-stream',
  `--use-file-for-fake-video-capture=${process.env.FAKE_CAMERA}`,
])

async function newUser() {
  const context = await browser.newContext({ viewport: { width: 1100, height: 1300 } })
  await context.grantPermissions(['camera'], { origin: WEB })
  const page = watch(await context.newPage())
  return { context, page }
}

const alice = await newUser()
const a = alice.page

await check('served with the production security headers from vercel.json', async () => {
  const response = await a.goto(`${WEB}/`)
  const headers = response.headers()
  if (!headers['content-security-policy']?.includes("default-src 'self'")) throw new Error('no CSP')
  if (!headers['permissions-policy']?.includes('camera=(self)')) throw new Error('camera not allowed')
  if (headers['x-frame-options'] !== 'DENY') throw new Error('frame protection missing')
})

await check('anonymous Firebase sign-in (Auth emulator) and profile from Flask', async () => {
  await a.goto(`${WEB}/account`)
  await a.getByRole('button', { name: 'Continue without an e-mail' }).click()
  await a.getByText('Signed in').waitFor({ timeout: 15000 })
  await a.getByText('Anonymous account on this device').waitFor()
  await a.getByLabel('Offer to save my results to my history').waitFor({ timeout: 15000 })
  if (!(await a.getByRole('link', { name: 'History', exact: true }).isVisible())) throw new Error('no history link')
})

await check('URL check -> demo blocklist hit 90 MALICIOUS (labelled demo data, not verified TI), saved to Firestore history', async () => {
  await a.getByRole('link', { name: 'Link', exact: true }).click()
  await a.locator('#url').fill('http://secure-sbi-kyc-update.example/login')
  if (!(await a.getByLabel(/Save the result to my history/).isChecked())) throw new Error('save not preselected')
  await a.getByRole('button', { name: 'Check link' }).click()
  await a.getByTestId('history-notice').waitFor({ timeout: 20000 })
  const text = await a.getByRole('article').innerText()
  if (!text.includes('MALICIOUS') || !text.includes("demo blocklist") || text.includes('Verified by threat intelligence')) throw new Error(text.slice(0, 150))
  if (!(await a.getByTestId('history-notice').innerText()).includes('Saved')) throw new Error('not saved')
  await a.screenshot({ path: `${ARTIFACTS}/web-e2e-url.png`, fullPage: true })
})

await check('report the result (linked to the saved scan)', async () => {
  await a.getByRole('button', { name: /Report it/ }).click()
  await a.getByLabel('It is genuine (wrongly flagged)').check()
  await a.getByLabel(/Note/).fill('E2E demo report')
  await a.getByRole('button', { name: 'Send report' }).click()
  await a.getByText(/your report was sent/).waitFor({ timeout: 10000 })
})

await check('message check saved; content never shown in history', async () => {
  await a.getByRole('link', { name: 'Message', exact: true }).click()
  await a.getByLabel('Message text').fill(
    'Dear customer, your SBI account will be BLOCKED today. Share the OTP and update KYC: http://sbi-kyc-update.xyz/login?t=E2ESECRET',
  )
  await a.getByRole('button', { name: 'Check message' }).click()
  await a.getByTestId('history-notice').waitFor({ timeout: 20000 })
})

await check('live camera QR scan (fake camera shows a UPI refund QR) -> SUSPICIOUS', async () => {
  await a.getByRole('link', { name: 'QR code', exact: true }).click()
  await a.getByRole('tab', { name: 'Use the camera' }).click()
  await a.getByTestId('qr-details').waitFor({ timeout: 30000 })
  const text = await a.getByRole('article').innerText()
  if (!text.includes('SUSPICIOUS') || !text.includes('refund.desk9912@okdemo')) throw new Error(text.slice(0, 200))
  await a.screenshot({ path: `${ARTIFACTS}/web-e2e-camera.png`, fullPage: true })
})

await check('history lists 3 verdicts, no message text or full URL', async () => {
  await a.getByRole('link', { name: 'History', exact: true }).click()
  await a.getByTestId('history-item').first().waitFor({ timeout: 15000 })
  const rows = await a.getByTestId('history-item').count()
  const text = await a.locator('main').innerText()
  if (rows !== 3) throw new Error(`rows=${rows}`)
  for (const secret of ['E2ESECRET', 'Dear customer', '/login', 'refund.desk9912']) {
    if (text.includes(secret)) throw new Error(`leaked ${secret}`)
  }
  if (!text.includes('UPI payment (@okdemo)')) throw new Error('upi target missing')
  await a.screenshot({ path: `${ARTIFACTS}/web-e2e-history.png`, fullPage: true })
})

const bob = await newUser()
await check('isolation: another user sees an empty history', async () => {
  await bob.page.goto(`${WEB}/account`)
  await bob.page.getByRole('button', { name: 'Continue without an e-mail' }).click()
  await bob.page.getByText('Signed in').waitFor({ timeout: 15000 })
  await bob.page.getByRole('link', { name: 'History', exact: true }).click()
  await bob.page.getByText('No saved results yet.').waitFor({ timeout: 15000 })
})

await check('admin: a normal user is refused (page and API)', async () => {
  await bob.page.goto(`${WEB}/admin`)
  await bob.page.getByText('Administrator access is required.').waitFor({ timeout: 10000 })
  if (await bob.page.getByRole('link', { name: 'Admin' }).count()) throw new Error('admin link shown')
})

await check('admin e-mail user: claim on sign-in, stats and report review', async () => {
  const admin = await newUser()
  const p = admin.page
  await p.goto(`${WEB}/account`)
  await p.getByLabel('E-mail').fill('admin@qrguard.test')
  await p.getByLabel('Password').fill('demo-password-123')
  await p.getByRole('button', { name: 'Create account' }).click()
  await p.getByText('Signed in').waitFor({ timeout: 15000 })
  // Grant the claim the way an operator would: the backend's `flask set-admin` command.
  const response = await fetch(`http://${AUTH_EMULATOR}/identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=demo-key`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'admin@qrguard.test', password: 'demo-password-123', returnSecureToken: true }),
  })
  const uid = (await response.json()).localId
  execFileSync(PY, ['-m', 'flask', '--app', 'wsgi', 'set-admin', uid], { cwd: BACKEND_DIR, stdio: 'inherit' })
  await p.getByRole('button', { name: 'Sign out' }).click()
  await p.getByLabel('E-mail').fill('admin@qrguard.test')
  await p.getByLabel('Password').fill('demo-password-123')
  await p.getByRole('button', { name: 'Sign in', exact: true }).click()
  await p.getByRole('link', { name: 'Admin' }).click({ timeout: 15000 })
  await p.getByTestId('stat-Checks').waitFor({ timeout: 15000 })
  const checks = Number(await p.getByTestId('stat-Checks').innerText())
  if (!(checks >= 3)) throw new Error(`checks=${checks}`)
  const report = p.getByTestId('admin-report').filter({ hasText: 'E2E demo report' })
  await report.waitFor({ timeout: 10000 })
  if ((await report.innerText()).includes('secure-sbi-kyc-update.example') === false) throw new Error('domain missing')
  await report.getByRole('button', { name: 'Mark as reviewed' }).click()
  await report.waitFor({ state: 'detached', timeout: 10000 })
  await p.screenshot({ path: `${ARTIFACTS}/web-e2e-admin.png`, fullPage: true })
})

await check('delete my data removes all history and signs out', async () => {
  await a.getByRole('link', { name: 'Account' }).click()
  await a.getByRole('button', { name: 'Delete my data' }).click()
  await a.getByRole('button', { name: 'Yes, delete everything' }).click()
  await a.getByRole('button', { name: 'Continue without an e-mail' }).waitFor({ timeout: 15000 })
})

await check('QR image upload -> decoded link, verdict, reasons and recommended action', async () => {
  // A photo of a QR code that points to a look-alike of flipkart.com (postman fixture).
  const fixture = fileURLToPath(new URL('../../postman/fixtures/qr-lookalike-link.png', import.meta.url))
  const u = await newUser()
  try {
    const p = u.page
    await p.goto(`${WEB}/check/qr`)
    await p.getByRole('tab', { name: 'Upload an image' }).click()
    await p.getByLabel('Image with a QR code').setInputFiles(fixture)
    await p.getByRole('button', { name: 'Check QR code' }).click()
    const result = p.getByRole('article', { name: 'Analysis result' })
    await result.waitFor({ timeout: 20000 })
    const decoded = await p.getByTestId('open-checked-link').innerText()
    if (!decoded.includes('https://flipkrat.com/rewards')) throw new Error(`decoded link: ${decoded.slice(0, 120)}`)
    const text = await result.innerText()
    if (!text.includes('MALICIOUS')) throw new Error(`verdict: ${text.slice(0, 120)}`)
    if (!(await p.getByTestId('verdict-title').innerText()).trim()) throw new Error('no verdict title')
    const section = (heading) => result.locator('section, div').filter({ has: p.getByRole('heading', { name: heading, exact: true }) }).last()
    if (!(await section('Why this result').innerText()).includes("Look-alike of a well-known brand's domain")) {
      throw new Error('look-alike reason missing')
    }
    if (!(await section('What you should do').innerText()).includes('Do not open, pay or connect using this QR code')) {
      throw new Error('recommended action missing')
    }
    // The advice comes straight after the verdict, before the score and the evidence.
    const nextAfterVerdict = await result.locator('header + section').getAttribute('data-testid')
    if (nextAfterVerdict !== 'recommendation') throw new Error(`section after the verdict: ${nextAfterVerdict}`)
    // No provider keys in this stack: only the demo blocklist answers, the rest are "Not configured",
    // and the summary says that an unchecked source is not evidence of safety.
    const summary = await result.getByTestId('ti-summary').innerText()
    if (!summary.startsWith('1 of 5 sources checked this link, 4 not configured.') || !summary.includes('says nothing about whether it is safe')) {
      throw new Error(`provider summary: ${summary}`)
    }
    const outcomes = await result.getByTestId('ti-provider').evaluateAll((rows) => rows.map((r) => r.dataset.outcome))
    if (outcomes.filter((o) => o === 'not_configured').length !== 4) throw new Error(`provider outcomes: ${outcomes}`)
    await p.screenshot({ path: `${ARTIFACTS}/web-e2e-qr-upload.png`, fullPage: true })
  } finally {
    await u.context.close()
  }
})

// ---- Screenshot OCR: image -> Tesseract -> scam-message engine -> result (no mocks) ----------------
const API = process.env.API_URL ?? 'http://127.0.0.1:5095'
const fixturePath = (name) => fileURLToPath(new URL(`../../postman/fixtures/${name}`, import.meta.url))
const isScreenshotCall = (r) => r.url().endsWith('/api/analyze/screenshot')

await check('screenshot upload -> OCR text -> scam analysis -> MALICIOUS with message and link reasons', async () => {
  // A rendered SMS (demo data): fake SBI "account blocked" + KYC link.
  const u = await newUser()
  try {
    const p = u.page
    await p.goto(`${WEB}/check/screenshot`)
    await p.getByLabel('Screenshot of the message').setInputFiles(fixturePath('scam-kyc.png'))
    const answered = p.waitForResponse(isScreenshotCall)
    await p.getByRole('button', { name: 'Check screenshot' }).click()
    await p.getByTestId('analysis-progress').getByText('Reading the text in the image (OCR)').waitFor({ timeout: 5000 })
    const response = await answered
    const body = await response.json()
    // The text really came out of OCR and really reached the message engine.
    const extracted = body.analysis?.ocr?.extracted_text ?? ''
    if (response.status() !== 200 || !/BLOCKED/i.test(extracted) || !/KYC/i.test(extracted)) {
      throw new Error(`OCR ${response.status()}: ${extracted.slice(0, 120)}`)
    }
    const sources = new Set(body.indicators.map((i) => i.source))
    if (!sources.has('message') || !sources.has('link')) throw new Error(`evidence sources: ${[...sources]}`)
    if (body.risk_level !== 'MALICIOUS') throw new Error(`level ${body.risk_level} ${body.risk_score}`)
    // ...and the page shows that result.
    const result = p.getByRole('article', { name: 'Analysis result' })
    await result.waitFor({ timeout: 5000 })
    const text = await result.innerText()
    for (const expected of ['MALICIOUS', 'What you should do', 'Message text']) {
      if (!text.includes(expected)) throw new Error(`missing "${expected}"`)
    }
    if (!/BLOCKED/i.test(await p.getByTestId('ocr-details').innerText())) throw new Error('OCR text not shown')
    await p.screenshot({ path: `${ARTIFACTS}/web-e2e-screenshot.png`, fullPage: true })
  } finally {
    await u.context.close()
  }
})

await check('screenshot without text -> "no text found" error, no result', async () => {
  const u = await newUser()
  try {
    const p = u.page
    await p.goto(`${WEB}/check/screenshot`)
    await p.getByLabel('Screenshot of the message').setInputFiles(fixturePath('blank.png'))
    const answered = p.waitForResponse(isScreenshotCall)
    await p.getByRole('button', { name: 'Check screenshot' }).click()
    const response = await answered
    if (response.status() !== 422 || (await response.json()).error?.code !== 'NO_TEXT_FOUND') throw new Error(`${response.status()}`)
    const alert = await p.getByRole('alert').innerText()
    if (!alert.includes('Could not complete the check') || !alert.includes('Try a sharper screenshot')) throw new Error(alert)
    if (await p.getByRole('article', { name: 'Analysis result' }).count()) throw new Error('a result was shown')
    if (!(await p.getByRole('button', { name: 'Check screenshot' }).isEnabled())) throw new Error('cannot retry')
  } finally {
    await u.context.close()
  }
})

await check('corrupted image -> unreadable-image error, no result', async () => {
  const u = await newUser()
  try {
    const p = u.page
    await p.goto(`${WEB}/check/screenshot`)
    await p.getByLabel('Screenshot of the message').setInputFiles(fixturePath('truncated.png'))
    const answered = p.waitForResponse(isScreenshotCall)
    await p.getByRole('button', { name: 'Check screenshot' }).click()
    const response = await answered
    if (response.status() !== 422 || (await response.json()).error?.code !== 'UNPROCESSABLE_IMAGE') throw new Error(`${response.status()}`)
    await p.getByRole('alert').waitFor({ timeout: 5000 })
    if (await p.getByRole('article', { name: 'Analysis result' }).count()) throw new Error('a result was shown')
  } finally {
    await u.context.close()
  }
})

await check('unsupported and oversized files are refused in the browser (nothing uploaded) and by the API', async () => {
  const u = await newUser()
  try {
    const p = u.page
    const uploads = []
    p.on('request', (r) => isScreenshotCall(r) && uploads.push(r.url()))
    await p.goto(`${WEB}/check/screenshot`)
    const input = p.getByLabel('Screenshot of the message')
    const button = p.getByRole('button', { name: 'Check screenshot' })
    await input.setInputFiles(fixturePath('not-an-image.txt'))
    await p.getByText('Please choose a PNG, JPEG or WEBP image.').waitFor({ timeout: 5000 })
    if (await button.isEnabled()) throw new Error('submit enabled for a text file')
    const big = Buffer.alloc(6 * 1024 * 1024, 0)
    big.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    await input.setInputFiles({ name: 'huge.png', mimeType: 'image/png', buffer: big })
    await p.getByText(/the limit is 5 MB/).waitFor({ timeout: 5000 })
    if (await button.isEnabled()) throw new Error('submit enabled for a 6 MB file')
    if (uploads.length) throw new Error('a file was uploaded')
    // The browser checks are a convenience: the API enforces the same rules itself.
    // Playwright's request client reads the server's early 413 answer (Node's fetch reports the
    // closed upload as a network error instead).
    const post = async (bytes, name, type) => {
      const response = await u.context.request.post(`${API}/api/analyze/screenshot`, {
        multipart: { file: { name, mimeType: type, buffer: bytes } },
      })
      return [response.status(), (await response.json().catch(() => ({}))).error?.code]
    }
    const text = await post(Buffer.from('hello'), 'note.txt', 'text/plain')
    if (text.join() !== '415,UNSUPPORTED_MEDIA_TYPE') throw new Error(`text file: ${text}`)
    // An oversized upload is refused from its declared size, before the body is read: send only
    // the headers of a 6 MB upload and read the answer (sending the body would hit a closed socket).
    const huge = await new Promise((resolve, reject) => {
      const req = http.request(`${API}/api/analyze/screenshot`, {
        method: 'POST',
        headers: { 'Content-Type': 'multipart/form-data; boundary=x', 'Content-Length': String(big.length) },
      })
      req.on('response', (res) => {
        let raw = ''
        res.on('data', (chunk) => (raw += chunk))
        res.on('end', () => {
          req.destroy()
          resolve([res.statusCode, JSON.parse(raw || '{}').error?.code])
        })
      })
      req.on('error', reject)
      req.flushHeaders()
    })
    if (huge.join() !== '413,PAYLOAD_TOO_LARGE') throw new Error(`6 MB upload: ${huge}`)
  } finally {
    await u.context.close()
  }
})

await check('QR generator renders a Wi-Fi code under the production CSP', async () => {
  const g = await newUser()
  await g.page.goto(`${WEB}/generate`)
  await g.page.getByLabel('Wi-Fi').click()
  await g.page.getByLabel('Network name (SSID)').fill('DemoNet')
  await g.page.getByLabel('Password').fill('demo-password-123')
  await g.page.getByRole('button', { name: 'Create QR code' }).click()
  const image = g.page.getByAltText('Generated QR code')
  await image.waitFor({ timeout: 10000 })
  const width = await image.evaluate((img) => (img.complete ? img.naturalWidth : 0))
  if (!(width > 0)) throw new Error('generated image did not load')
})

await check('mobile width: no horizontal scroll on the result page', async () => {
  const m = await newUser()
  await m.page.setViewportSize({ width: 375, height: 800 })
  await m.page.goto(`${WEB}/check/url`)
  await m.page.locator('#url').fill('https://flipkrat.com/rewards')
  await m.page.getByRole('button', { name: 'Check link' }).click()
  await m.page.getByRole('article').waitFor({ timeout: 20000 })
  const overflow = await m.page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)
  if (overflow) throw new Error('horizontal overflow')
})

// "Open checked link": a real browser with Chromium's popup blocker ON (Playwright turns it off by
// default). Every navigation that leaves this machine is answered by a stub, so no external site
// is ever contacted; the checked URL is never fetched by the backend (not a shortener).
const OPEN_URL = 'https://example.com/offer'
const realBrowser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  ignoreDefaultArgs: ['--disable-popup-blocking'],
})

async function linkContext({ refuseScriptedPopups = false } = {}) {
  const context = await realBrowser.newContext({ viewport: { width: 1100, height: 1300 } })
  const external = []
  await context.route(/^https?:\/\/(?!(localhost|127\.0\.0\.1)[:/])/, (route) => {
    external.push(route.request().url())
    return route.fulfill({ status: 200, contentType: 'text/html', body: '<title>stub destination</title>stub' })
  })
  // Simulates a browser, extension or in-app browser that refuses scripted popups.
  if (refuseScriptedPopups) await context.addInitScript(() => { window.open = () => null })
  const page = watch(await context.newPage())
  return { context, page, external }
}

async function checkLink(page, url) {
  await page.goto(`${WEB}/check/url`)
  await page.locator('#url').fill(url)
  await page.getByRole('button', { name: 'Check link' }).click()
  await page.getByRole('article').waitFor({ timeout: 20000 })
}

async function confirmAndOpen(context, page) {
  await page.getByRole('button', { name: 'Open checked link' }).click()
  const dialog = page.getByTestId('open-link-confirm')
  if (!(await dialog.innerText()).includes(OPEN_URL)) throw new Error('confirmation does not show the checked URL')
  const [popup] = await Promise.all([
    context.waitForEvent('page', { timeout: 10000 }),
    // By its text, whatever the element is, so the check measures behaviour, not markup.
    dialog.getByText('Open example.com in a new tab', { exact: true }).click({ timeout: 10000 }),
  ])
  await popup.waitForLoadState()
  return popup
}

await check('open checked link: confirming opens exactly the checked URL in a new tab (popup blocker on)', async () => {
  const { context, page, external } = await linkContext()
  try {
    await checkLink(page, OPEN_URL)
    if (external.length) throw new Error(`contacted before confirmation: ${external.join(' ')}`)
    const popup = await confirmAndOpen(context, page)
    if (popup.url() !== OPEN_URL) throw new Error(`opened ${popup.url()}`)
    if ((await popup.evaluate(() => window.opener)) !== null) throw new Error('new tab has an opener')
    if (!page.url().startsWith(WEB)) throw new Error('the app tab navigated away')
    await page.getByTestId('open-link-confirm').waitFor({ state: 'detached', timeout: 5000 })
  } finally {
    await context.close()
  }
})

await check('open checked link: still opens when the browser refuses scripted popups', async () => {
  const { context, page } = await linkContext({ refuseScriptedPopups: true })
  try {
    await checkLink(page, OPEN_URL)
    const popup = await confirmAndOpen(context, page)
    if (popup.url() !== OPEN_URL) throw new Error(`opened ${popup.url()}`)
  } finally {
    await context.close()
  }
})

await check('open checked link: cancel opens nothing', async () => {
  const { context, page, external } = await linkContext()
  try {
    await checkLink(page, OPEN_URL)
    let opened = false
    context.on('page', () => { opened = true })
    await page.getByRole('button', { name: 'Open checked link' }).click()
    await page.getByRole('button', { name: 'Cancel' }).click()
    await page.waitForTimeout(1500)
    if (opened || external.length) throw new Error('something was opened after Cancel')
    if (await page.getByTestId('open-link-confirm').count()) throw new Error('confirmation still shown')
  } finally {
    await context.close()
  }
})

await check('open checked link: user@host disguise and non-web links are never offered', async () => {
  const { context, page } = await linkContext()
  try {
    await checkLink(page, 'https://paypal.com@evil.example/login')
    await page.getByTestId('never-open-reason').waitFor()
    if (await page.getByRole('button', { name: /Open checked link/ }).count()) throw new Error('open offered for user@host')
    // javascript: is analysed (MALICIOUS, dangerous scheme) but must never be openable.
    await checkLink(page, 'javascript:alert(1)')
    await page.getByTestId('never-open-reason').waitFor()
    if (!(await page.getByRole('article').innerText()).includes('MALICIOUS')) throw new Error('javascript: not flagged')
    if (await page.getByRole('button', { name: /Open checked link/ }).count()) throw new Error('open offered for javascript:')
  } finally {
    await context.close()
  }
})

await realBrowser.close()
await browser.close()
finish()
