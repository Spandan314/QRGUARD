import { FirebaseAuthClient } from './auth'

const fake = vi.hoisted(() => {
  const state: { user: { uid: string; isAnonymous: boolean; email: string | null; getIdToken: () => Promise<string> } | null } = {
    user: null,
  }
  const listeners = new Set<(user: unknown) => void>()
  const auth = {
    get currentUser() {
      return state.user
    },
  }
  const emit = () => listeners.forEach((listener) => listener(state.user))
  const signIn = (uid: string, isAnonymous: boolean, email: string | null) => {
    state.user = { uid, isAnonymous, email, getIdToken: async () => `token-${uid}` }
    emit()
  }
  // Plain functions (not vi.fn): the shared setup restores mocks after each test.
  const calls: Record<string, unknown[][]> = {}
  const record =
    <A extends unknown[], R>(name: string, fn: (...args: A) => R) =>
    (...args: A): R => {
      ;(calls[name] ??= []).push(args)
      return fn(...args)
    }
  return {
    state,
    auth,
    calls,
    initializeApp: record('initializeApp', () => ({})),
    getAuth: record('getAuth', () => auth),
    connectAuthEmulator: record('connectAuthEmulator', () => undefined),
    onIdTokenChanged: record('onIdTokenChanged', (_auth: unknown, listener: (user: unknown) => void) => {
      listeners.add(listener)
      listener(state.user)
      return () => {
        listeners.delete(listener)
      }
    }),
    signInAnonymously: record('signInAnonymously', async () => signIn('anon-1', true, null)),
    signInWithEmailAndPassword: record('signInWithEmailAndPassword', async (_a: unknown, email: string) =>
      signIn('mail-1', false, email),
    ),
    createUserWithEmailAndPassword: record('createUserWithEmailAndPassword', async (_a: unknown, email: string) =>
      signIn('new-1', false, email),
    ),
    signOut: record('signOut', async () => {
      state.user = null
      emit()
    }),
  }
})

vi.mock('firebase/app', () => ({ initializeApp: fake.initializeApp }))
vi.mock('firebase/auth', () => ({
  getAuth: fake.getAuth,
  connectAuthEmulator: fake.connectAuthEmulator,
  onIdTokenChanged: fake.onIdTokenChanged,
  signInAnonymously: fake.signInAnonymously,
  signInWithEmailAndPassword: fake.signInWithEmailAndPassword,
  createUserWithEmailAndPassword: fake.createUserWithEmailAndPassword,
  signOut: fake.signOut,
}))

describe('FirebaseAuthClient', () => {
  beforeEach(() => {
    fake.state.user = null
    vi.stubEnv('VITE_FIREBASE_API_KEY', 'public-web-key')
    vi.stubEnv('VITE_FIREBASE_PROJECT_ID', 'demo-qrguard')
    vi.stubEnv('VITE_FIREBASE_AUTH_EMULATOR_HOST', '127.0.0.1:9099')
  })
  afterEach(() => vi.unstubAllEnvs())

  it('uses the public config and the emulator when configured', async () => {
    const client = new FirebaseAuthClient()
    expect(await client.getToken()).toBeNull()
    expect(fake.calls.initializeApp?.[0]?.[0]).toEqual(expect.objectContaining({ apiKey: 'public-web-key', projectId: 'demo-qrguard' }))
    expect(fake.calls.connectAuthEmulator?.[0]).toEqual([fake.auth, 'http://127.0.0.1:9099', { disableWarnings: true }])
  })

  it('signs in anonymously, with e-mail and new accounts, reports users and tokens, signs out', async () => {
    const client = new FirebaseAuthClient()
    const seen: (string | null)[] = []
    const stop = client.onChange((user) => seen.push(user ? `${user.uid}:${user.isAnonymous}` : null))
    await vi.waitFor(() => expect(seen).toEqual([null]))
    await client.signInAnonymously()
    expect(await client.getToken()).toBe('token-anon-1')
    await client.signInWithEmail('a@b.in', 'pw123456', false)
    await client.signInWithEmail('c@d.in', 'pw123456', true)
    expect(fake.calls.createUserWithEmailAndPassword?.at(-1)).toEqual([fake.auth, 'c@d.in', 'pw123456'])
    await client.signOut()
    stop()
    expect(seen).toEqual([null, 'anon-1:true', 'mail-1:false', 'new-1:false', null])
  })

  it('does not subscribe if unsubscribed before Firebase loaded', async () => {
    const client = new FirebaseAuthClient()
    const listener = vi.fn()
    client.onChange(listener)()
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(listener).not.toHaveBeenCalled()
  })
})
