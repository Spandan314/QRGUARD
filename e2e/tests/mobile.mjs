// Mobile app screens (Expo web export, Firebase mode) -> Auth emulator -> Flask -> Firestore emulator.
// The native camera cannot be driven here; see docs/testing.md for the device checklist.
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

await check('delete my data (confirmation dialog) signs out', async () => {
  await p.getByRole('tab', { name: /Account/ }).click()
  p.once('dialog', (dialog) => void dialog.accept())
  await p.getByText('Delete my data', { exact: true }).click()
  await p.getByText('Continue without an e-mail', { exact: true }).waitFor({ timeout: 20000 })
})

await browser.close()
finish()
