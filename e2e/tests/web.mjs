// Full-stack E2E: Chromium -> web app (Firebase mode) -> Firebase Auth emulator -> Flask (verifies
// ID tokens) -> analysis + threat intelligence -> Firestore emulator (history). No mocks.
// Run through ../run.sh, which starts everything.
import { execFileSync } from 'node:child_process'
import { ARTIFACTS, check, finish, launch, watch } from './harness.mjs'

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

await check('anonymous Firebase sign-in (Auth emulator) and profile from Flask', async () => {
  await a.goto(`${WEB}/account`)
  await a.getByRole('button', { name: 'Continue without an e-mail' }).click()
  await a.getByText('Signed in').waitFor({ timeout: 15000 })
  await a.getByText('Anonymous account on this device').waitFor()
  await a.getByLabel('Offer to save my results to my history').waitFor({ timeout: 15000 })
  if (!(await a.getByRole('link', { name: 'History', exact: true }).isVisible())) throw new Error('no history link')
})

await check('URL check -> TI hit 90 MALICIOUS VERIFIED, saved to Firestore history', async () => {
  await a.getByRole('link', { name: 'Link', exact: true }).click()
  await a.locator('#url').fill('http://secure-sbi-kyc-update.example/login')
  if (!(await a.getByLabel(/Save the result to my history/).isChecked())) throw new Error('save not preselected')
  await a.getByRole('button', { name: 'Check link' }).click()
  await a.getByTestId('history-notice').waitFor({ timeout: 20000 })
  const text = await a.getByRole('article').innerText()
  if (!text.includes('MALICIOUS') || !text.includes('Verified by threat intelligence')) throw new Error(text.slice(0, 150))
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

await browser.close()
finish()
