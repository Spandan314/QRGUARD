import { authErrorMessage, authMode, createAuthClient, DevAuthClient, FirebaseAuthClient, NoAuthClient } from './auth'

describe('auth client selection', () => {
  afterEach(() => vi.unstubAllEnvs())

  it('is off without configuration and follows VITE_AUTH_MODE', () => {
    vi.stubEnv('VITE_AUTH_MODE', '')
    vi.stubEnv('VITE_FIREBASE_API_KEY', '')
    expect(authMode()).toBe('off')
    vi.stubEnv('VITE_FIREBASE_API_KEY', 'public-web-key')
    expect(authMode()).toBe('firebase')
    vi.stubEnv('VITE_AUTH_MODE', 'dev')
    expect(authMode()).toBe('dev')
  })

  it('creates the matching client', () => {
    expect(createAuthClient('dev')).toBeInstanceOf(DevAuthClient)
    expect(createAuthClient('off')).toBeInstanceOf(NoAuthClient)
    expect(createAuthClient('firebase')).toBeInstanceOf(FirebaseAuthClient)
  })
})

describe('DevAuthClient', () => {
  beforeEach(() => sessionStorage.clear())

  it('signs in, notifies listeners, returns the token and signs out', async () => {
    const client = new DevAuthClient()
    const seen: (string | null)[] = []
    const stop = client.onChange((user) => seen.push(user?.uid ?? null))
    await client.signInDemo(' Alice!! ', false)
    expect(await client.getToken()).toBe('dev-alice')
    await client.signInDemo('root', true)
    expect(await client.getToken()).toBe('dev-admin-root')
    await client.signOut()
    expect(await client.getToken()).toBeNull()
    stop()
    expect(seen).toEqual([null, 'dev-alice', 'dev-root', null])
  })

  it('rejects names that are too short', async () => {
    await expect(new DevAuthClient().signInDemo('a!', false)).rejects.toThrow(/at least 3/)
  })
})

describe('authErrorMessage', () => {
  it('maps Firebase codes to plain language without leaking details', () => {
    expect(authErrorMessage({ code: 'auth/invalid-credential', message: 'raw' })).toBe('Wrong e-mail or password.')
    expect(authErrorMessage({ code: 'auth/weak-password' })).toMatch(/6 characters/)
    expect(authErrorMessage({ code: 'auth/something-new', message: 'internal detail' })).toBe('Sign-in failed. Please try again.')
    expect(authErrorMessage(new Error('Use at least 3 letters or digits.'))).toBe('Use at least 3 letters or digits.')
  })
})

describe('NoAuthClient', () => {
  it('is always signed out', async () => {
    const client = new NoAuthClient()
    const seen: unknown[] = []
    client.onChange((user) => seen.push(user))
    expect(seen).toEqual([null])
    expect(await client.getToken()).toBeNull()
  })
})
