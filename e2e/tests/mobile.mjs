// Mobile app screens (Expo web export, Firebase mode) -> Auth emulator -> Flask -> Firestore emulator.
// The native camera cannot be driven here; see docs/testing.md for the device checklist.
import { fileURLToPath } from 'node:url'
import { ARTIFACTS, check, finish, launch, watch } from './harness.mjs'

const APP = process.env.MOBILE_URL ?? 'http://localhost:8083'
const browser = await launch()
async function phone() {
  return watch(await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 }))
}
const p = await phone()

await check('Account tab: anonymous Firebase sign-in', async () => {
  await p.goto(APP)
  await p.getByRole('tab', { name: /Sign in/ }).click()
  await p.getByText('Continue without an e-mail', { exact: true }).click()
  await p.getByText('Signed in', { exact: true }).waitFor({ timeout: 20000 })
  await p.getByLabel('Offer to save my results to my history').waitFor({ timeout: 15000 })
})

await check('link check saved to history (Authorization + save_to_history)', async () => {
  await p.getByRole('tab', { name: /Home/ }).click()
  await p.getByLabel('Check a link').click()
  await p.getByLabel('Link', { exact: true }).fill('http://secure-sbi-kyc-update.example/login')
  await p.getByText('Check link', { exact: true }).click()
  await p.getByTestId('history-notice').waitFor({ timeout: 20000 })
  const text = await p.getByTestId('result-view').innerText()
  if (!text.includes('MALICIOUS') || !(await p.getByTestId('history-notice').innerText()).includes('Saved')) {
    throw new Error(text.slice(0, 200))
  }
  await p.screenshot({ path: `${ARTIFACTS}/mobile-result.png` })
})

await check('History tab shows the verdict without the full link', async () => {
  await p.goto(APP)
  await p.getByRole('tab', { name: /History/ }).click()
  await p.getByTestId('history-item').first().waitFor({ timeout: 20000 })
  const text = await p.locator('body').innerText()
  if (!text.includes('Link · secure-sbi-kyc-update.example') || text.includes('/login')) throw new Error(text.slice(0, 300))
  await p.screenshot({ path: `${ARTIFACTS}/mobile-history.png` })
})

await check('another phone user sees no history', async () => {
  const q = await phone()
  await q.goto(APP)
  await q.getByRole('tab', { name: /Sign in/ }).click()
  await q.getByText('Continue without an e-mail', { exact: true }).click()
  await q.getByText('Signed in', { exact: true }).waitFor({ timeout: 20000 })
  await q.getByRole('tab', { name: /History/ }).click()
  await q.getByText('No saved results yet.').waitFor({ timeout: 20000 })
})

// ---- Message and image (screenshot OCR) journeys, through the real backend ------------------------
const fixturePath = (name) => fileURLToPath(new URL(`../../postman/fixtures/${name}`, import.meta.url))
const SCAM_SMS = 'Dear customer, your SBI account will be BLOCKED today. Update your KYC now: http://sbi-kyc-update.xyz/login'
const isCall = (path) => (r) => r.url().endsWith(path)

async function openHomeAction(label, page = p) {
  await page.goto(APP)
  await page.getByRole('tab', { name: /Home/ }).click()
  await page.getByLabel(label).click()
}
// Simulated outages make the browser log network errors on purpose, so they run in a page that is
// not watched for console errors.
const flaky = await browser.newPage({ viewport: { width: 390, height: 844 } })

await check('message check: text reaches /api/analyze/message (signed in) and the explained result is shown', async () => {
  await openHomeAction('Check a message')
  const button = p.getByRole('button', { name: 'Check message' })
  if ((await button.getAttribute('aria-disabled')) !== 'true') throw new Error('enabled with no text')
  await p.getByLabel('Message text').fill(SCAM_SMS)
  const sent = p.waitForRequest(isCall('/api/analyze/message'))
  const answered = p.waitForResponse(isCall('/api/analyze/message'))
  await button.click()
  const request = await sent
  const payload = JSON.parse(request.postData() ?? '{}')
  if (payload.text !== SCAM_SMS) throw new Error('message text was not sent unchanged')
  if (!(request.headers().authorization ?? '').startsWith('Bearer ')) throw new Error('no ID token sent')
  const body = await (await answered).json()
  // The fake-KYC SMS is a scam: the engine must flag it (it scores SUSPICIOUS), never clear it.
  if (!['SUSPICIOUS', 'MALICIOUS'].includes(body.verdict?.label)) throw new Error(`API: ${body.verdict?.label} ${body.risk_score}`)
  if (!body.indicators.some((i) => i.source === 'message')) throw new Error('no message evidence')
  await p.getByTestId('result-view').waitFor({ timeout: 20000 })
  const text = await p.getByTestId('result-view').innerText()
  for (const expected of [body.verdict.label, 'What you should do', 'Why this result']) {
    if (!text.includes(expected)) throw new Error(`missing "${expected}"`)
  }
  await p.screenshot({ path: `${ARTIFACTS}/mobile-message.png` })
})

await check('image check: screenshot -> OCR -> scam analysis -> MALICIOUS result with the text read', async () => {
  await openHomeAction('Choose image to check')
  const chooser = p.waitForEvent('filechooser')
  await p.getByRole('button', { name: 'Choose image to check' }).click()
  await (await chooser).setFiles(fixturePath('scam-kyc.png'))
  await p.getByLabel('Selected image').waitFor({ timeout: 20000 })
  const answered = p.waitForResponse(isCall('/api/analyze/screenshot'), { timeout: 60000 })
  await p.getByRole('button', { name: 'Check image' }).click()
  const response = await answered
  const body = await response.json()
  if (response.status() !== 200 || !/KYC/i.test(body.analysis?.ocr?.extracted_text ?? '')) {
    throw new Error(`OCR ${response.status()}: ${JSON.stringify(body).slice(0, 160)}`)
  }
  if (!body.indicators.some((i) => i.source === 'message')) throw new Error('OCR text did not reach the message engine')
  await p.getByTestId('result-view').waitFor({ timeout: 20000 })
  const text = await p.getByTestId('result-view').innerText()
  if (!text.includes('MALICIOUS') || !/BLOCKED/i.test(text)) throw new Error(text.slice(0, 200))
  await p.screenshot({ path: `${ARTIFACTS}/mobile-image.png` })
})

await check('image check: an image without text shows "no text" guidance, no result', async () => {
  await openHomeAction('Choose image to check')
  const chooser = p.waitForEvent('filechooser')
  await p.getByRole('button', { name: 'Choose image to check' }).click()
  await (await chooser).setFiles(fixturePath('blank.png'))
  await p.getByLabel('Selected image').waitFor({ timeout: 20000 })
  await p.getByRole('button', { name: 'Check image' }).click()
  const banner = p.getByTestId('error-banner')
  await banner.waitFor({ timeout: 60000 })
  if (!(await banner.innerText()).includes('Choose a screenshot where the message text is clearly visible')) {
    throw new Error(await banner.innerText())
  }
  if (await p.getByTestId('result-view').count()) throw new Error('a result was shown')
})

await check('message check: unreachable server -> retryable error; "Try again" then succeeds', async () => {
  await openHomeAction('Check a message', flaky)
  await flaky.getByLabel('Message text').fill(SCAM_SMS)
  await flaky.route('**/api/analyze/message', (route) => route.abort('connectionrefused'))
  await flaky.getByRole('button', { name: 'Check message' }).click()
  const banner = flaky.getByTestId('error-banner')
  await banner.waitFor({ timeout: 20000 })
  if (!(await banner.innerText()).includes('Cannot reach the QRGUARD server')) throw new Error(await banner.innerText())
  await flaky.unroute('**/api/analyze/message')
  await flaky.getByRole('button', { name: 'Try again' }).click()
  await flaky.getByTestId('result-view').waitFor({ timeout: 20000 })
})

await check('message check: a rejected sign-in token is refused by the backend and explained', async () => {
  await openHomeAction('Check a message')
  await p.getByLabel('Message text').fill(SCAM_SMS)
  // Corrupt the real ID token on its way out: the real backend must refuse it (no faked answer).
  await p.route('**/api/analyze/message', (route) =>
    route.continue({ headers: { ...route.request().headers(), authorization: 'Bearer not-a-valid-token' } }),
  )
  const answered = p.waitForResponse(isCall('/api/analyze/message'))
  await p.getByRole('button', { name: 'Check message' }).click()
  const response = await answered
  if (response.status() !== 401 || (await response.json()).error?.code !== 'INVALID_TOKEN') throw new Error(`${response.status()}`)
  const banner = await p.getByTestId('error-banner').innerText()
  if (!banner.includes('sign in again in the Account tab')) throw new Error(banner)
  if (await p.getByTestId('result-view').count()) throw new Error('a result was shown')
  await p.unroute('**/api/analyze/message')
  await p.goto(APP)
})

await check('message check: a request that never answers ends with a timeout error, not a result', async () => {
  await openHomeAction('Check a message', flaky)
  await flaky.getByLabel('Message text').fill(SCAM_SMS)
  await flaky.route('**/api/analyze/message', () => {}) // never answered: the app's own 45 s timeout must fire
  await flaky.getByRole('button', { name: 'Check message' }).click()
  const banner = flaky.getByTestId('error-banner')
  await banner.waitFor({ timeout: 60000 })
  if (!(await banner.innerText()).includes('The check took too long')) throw new Error(await banner.innerText())
  if (!(await flaky.getByRole('button', { name: 'Try again' }).count())) throw new Error('no retry offered')
  await flaky.unroute('**/api/analyze/message')
})

await check('delete my data (confirmation dialog) signs out', async () => {
  await p.getByRole('tab', { name: /Account/ }).click()
  p.once('dialog', (dialog) => void dialog.accept())
  await p.getByText('Delete my data', { exact: true }).click()
  await p.getByText('Continue without an e-mail', { exact: true }).waitFor({ timeout: 20000 })
})

await browser.close()
finish()
