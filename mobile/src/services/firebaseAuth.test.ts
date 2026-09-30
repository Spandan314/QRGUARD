import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals'
import { FirebaseAuthClient } from './auth'

type User = { uid: string; isAnonymous: boolean; email: string | null; getIdToken: () => Promise<string> }
const mockState: { user: User | null; listeners: Set<(user: User | null) => void>; calls: Record<string, unknown[][]> } = {
  user: null,
  listeners: new Set(),
  calls: {},
}

jest.mock('firebase/app', () => ({
  initializeApp: (config: unknown) => {
    ;(mockState.calls.initializeApp ??= []).push([config])
    return { name: 'app' }
  },
}))

jest.mock('firebase/auth', () => {
  const auth = {
    get currentUser() {
      return mockState.user
    },
  }
  const emit = () => mockState.listeners.forEach((listener) => listener(mockState.user))
  const signIn = (uid: string, isAnonymous: boolean, email: string | null) => {
    mockState.user = { uid, isAnonymous, email, getIdToken: async () => `token-${uid}` }
    emit()
  }
  const record = (name: string, args: unknown[]) => (mockState.calls[name] ??= []).push(args)
  return {
    getReactNativePersistence: (storage: unknown) => {
      record('getReactNativePersistence', [storage])
      return 'rn-persistence'
    },
    initializeAuth: (app: unknown, options: unknown) => {
      record('initializeAuth', [app, options])
      return auth
    },
    getAuth: () => auth,
    connectAuthEmulator: (...args: unknown[]) => record('connectAuthEmulator', args),
    onIdTokenChanged: (_auth: unknown, listener: (user: User | null) => void) => {
      mockState.listeners.add(listener)
      listener(mockState.user)
      return () => mockState.listeners.delete(listener)
    },
    signInAnonymously: async () => signIn('anon-1', true, null),
    signInWithEmailAndPassword: async (_a: unknown, email: string) => signIn('mail-1', false, email),
    createUserWithEmailAndPassword: async (_a: unknown, email: string) => signIn('new-1', false, email),
    signOut: async () => {
      mockState.user = null
      emit()
    },
  }
})

describe('FirebaseAuthClient (React Native)', () => {
  const saved = { ...process.env }
  beforeEach(() => {
    mockState.user = null
    mockState.calls = {}
    process.env.EXPO_PUBLIC_FIREBASE_API_KEY = 'public-key'
    process.env.EXPO_PUBLIC_FIREBASE_PROJECT_ID = 'demo-qrguard'
    process.env.EXPO_PUBLIC_FIREBASE_AUTH_EMULATOR_HOST = '10.0.2.2:9099'
  })
  afterEach(() => {
    process.env = { ...saved }
  })

  it('keeps the session in AsyncStorage and uses the emulator when configured', async () => {
    const client = new FirebaseAuthClient()
    expect(await client.getToken()).toBeNull()
    expect(mockState.calls.initializeApp?.[0]?.[0]).toEqual(expect.objectContaining({ apiKey: 'public-key', projectId: 'demo-qrguard' }))
    expect(mockState.calls.initializeAuth?.[0]?.[1]).toEqual({ persistence: 'rn-persistence' })
    expect(mockState.calls.connectAuthEmulator?.[0]?.[1]).toBe('http://10.0.2.2:9099')
  })

  it('signs in and out and reports users and tokens', async () => {
    const client = new FirebaseAuthClient()
    const seen: (string | null)[] = []
    const stop = client.onChange((user) => seen.push(user ? user.uid : null))
    await client.signInAnonymously()
    expect(await client.getToken()).toBe('token-anon-1')
    await client.signInWithEmail('a@b.in', 'secret123', false)
    await client.signInWithEmail('c@d.in', 'secret123', true)
    await client.signOut()
    stop()
    expect(seen).toEqual([null, 'anon-1', 'mail-1', 'new-1', null])
  })
})
