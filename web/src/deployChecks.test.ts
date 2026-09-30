import { describe, expect, it } from 'vitest'
import { deployProblems } from './deployChecks'

describe('deployProblems', () => {
  it('accepts a hosted build pointing at an https backend', () => {
    expect(deployProblems({ VITE_API_BASE_URL: 'https://qrguard-api.onrender.com', VITE_AUTH_MODE: 'firebase' })).toEqual([])
  })

  it('rejects a missing or plain-http backend URL, dev accounts and the Auth emulator', () => {
    expect(deployProblems({})).toHaveLength(1)
    const problems = deployProblems({
      VITE_API_BASE_URL: 'http://localhost:5000',
      VITE_AUTH_MODE: 'dev',
      VITE_FIREBASE_AUTH_EMULATOR_HOST: '127.0.0.1:9099',
    })
    expect(problems).toHaveLength(3)
    expect(problems.join(' ')).toMatch(/https:\/\//)
  })
})
