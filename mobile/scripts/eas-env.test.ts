import { describe, expect, it } from '@jest/globals'
import { spawnSync } from 'node:child_process'
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Runs the real script against a fake `eas` binary that records each call.
const SCRIPT = join(__dirname, 'eas-env.sh')
const VALID = {
  EAS_PROJECT_ID: '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b',
  API_BASE_URL: 'https://qrguard-api.onrender.com',
  FIREBASE_API_KEY: 'public-web-api-key',
  FIREBASE_AUTH_DOMAIN: 'qrguard-demo.firebaseapp.com',
  FIREBASE_PROJECT_ID: 'qrguard-demo',
  FIREBASE_APP_ID: '1:123:web:abc',
}

function run(values: Record<string, string>, args: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), 'eas-env-'))
  const log = join(dir, 'calls.log')
  const fake = join(dir, 'eas')
  writeFileSync(fake, `#!/usr/bin/env bash\necho "$*" >> "${log}"\n`)
  chmodSync(fake, 0o755)
  const result = spawnSync('bash', [SCRIPT, ...args], {
    // A minimal environment on purpose: only PATH, the fake eas and the values under test.
    env: { PATH: process.env.PATH, EAS_BIN: fake, ...values } as unknown as NodeJS.ProcessEnv,
    encoding: 'utf8',
  })
  let calls: string[] = []
  try {
    calls = readFileSync(log, 'utf8').trim().split('\n')
  } catch {
    calls = []
  }
  return { ...result, calls }
}

describe('scripts/eas-env.sh', () => {
  it('sets all six variables in both preview and production', () => {
    const { status, calls } = run(VALID)
    expect(status).toBe(0)
    expect(calls).toHaveLength(12)
    expect(calls).toContain(
      'env:set preview --name EXPO_PUBLIC_API_BASE_URL --value https://qrguard-api.onrender.com --visibility plaintext --non-interactive',
    )
    expect(calls).toContain(
      `env:set production --name EAS_PROJECT_ID --value ${VALID.EAS_PROJECT_ID} --visibility plaintext --non-interactive`,
    )
  })

  it('only prints the commands with --dry-run', () => {
    const { status, calls, stdout } = run(VALID, ['--dry-run'])
    expect(status).toBe(0)
    expect(calls).toEqual([])
    expect(stdout.trim().split('\n')).toHaveLength(12)
  })

  it.each([
    ['plain http', { API_BASE_URL: 'http://qrguard-api.onrender.com' }],
    ['a trailing slash', { API_BASE_URL: 'https://qrguard-api.onrender.com/' }],
    ['a local address', { API_BASE_URL: 'https://localhost:5000' }],
    ['an emulator-only Firebase project', { FIREBASE_PROJECT_ID: 'demo-qrguard' }],
    ['a malformed EAS project ID', { EAS_PROJECT_ID: 'not-a-uuid' }],
    ['a missing value', { FIREBASE_APP_ID: '' }],
  ])('refuses %s without calling eas', (_label, override) => {
    const { status, calls, stderr } = run({ ...VALID, ...override })
    expect(status).toBe(2)
    expect(calls).toEqual([])
    expect(stderr).toMatch(/^eas-env: /)
  })
})
