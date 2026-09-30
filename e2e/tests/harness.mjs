// Tiny test harness shared by the E2E scripts: named checks, console-error capture, exit code.
import { chromium } from 'playwright-core'

export const ARTIFACTS = process.env.E2E_ARTIFACTS ?? 'artifacts'
const results = []
const problems = []

export async function check(name, fn) {
  try {
    await fn()
    results.push({ name, ok: true })
    console.log(`PASS ${name}`)
  } catch (error) {
    results.push({ name, ok: false })
    console.log(`FAIL ${name}: ${String(error.message).split('\n')[0]}`)
  }
}

export async function launch(args = []) {
  // CHROMIUM_PATH: a local Chromium/Chrome binary. Without it, Playwright's own browser is used.
  return chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args })
}

/** Records page errors and console errors, except expected HTTP 4xx answers. */
export function watch(page) {
  page.on('pageerror', (error) => problems.push(String(error)))
  page.on('console', (message) => {
    if (message.type() === 'error' && !/status of 4\d\d/.test(message.text())) problems.push(message.text())
  })
  return page
}

export function finish() {
  if (problems.length) console.log(`CONSOLE/PAGE ERRORS: ${problems.join(' | ').slice(0, 800)}`)
  const failed = results.filter((r) => !r.ok).length
  console.log(`${results.length - failed}/${results.length} checks passed`)
  process.exitCode = failed || problems.length ? 1 : 0
}
