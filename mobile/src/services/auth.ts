// Sign-in for the mobile app (same design as web/src/services/auth.ts):
//   firebase  Firebase Authentication (anonymous or e-mail/password), session kept in AsyncStorage.
//             EXPO_PUBLIC_FIREBASE_* are the public app config, not secrets.
//   dev       demo accounts ("dev-<name>" tokens) for a backend with AUTH_DEV_TOKENS=true
//             (refused by the backend in production).
//   off       no sign-in; all checks still work.
import AsyncStorage from '@react-native-async-storage/async-storage'

export type AuthMode = 'firebase' | 'dev' | 'off'

export interface SessionUser {
  uid: string
  isAnonymous: boolean
  email: string | null
}

export interface AuthClient {
  readonly mode: AuthMode
  onChange(listener: (user: SessionUser | null) => void): () => void
  getToken(): Promise<string | null>
  signOut(): Promise<void>
  signInAnonymously?(): Promise<void>
  signInWithEmail?(email: string, password: string, create: boolean): Promise<void>
  signInDemo?(name: string, admin: boolean): Promise<void>
}

export function authMode(): AuthMode {
  const configured = process.env.EXPO_PUBLIC_AUTH_MODE
  if (configured === 'firebase' || configured === 'dev' || configured === 'off') return configured
  return process.env.EXPO_PUBLIC_FIREBASE_API_KEY ? 'firebase' : 'off'
}

// ----- dev (demo) -------------------------------------------------------------------------------
const DEV_KEY = 'qrguard.devToken'
const DEV_TOKEN_RE = /^dev-(?:admin-)?([A-Za-z0-9_-]{3,64})$/

export class DevAuthClient implements AuthClient {
  readonly mode = 'dev' as const
  private listeners = new Set<(user: SessionUser | null) => void>()
  private token: string | null = null
  private loaded: Promise<void>

  constructor() {
    this.loaded = AsyncStorage.getItem(DEV_KEY)
      .then((value) => {
        this.token = value
      })
      .catch(() => undefined)
  }

  private user(): SessionUser | null {
    const match = this.token ? DEV_TOKEN_RE.exec(this.token) : null
    return match ? { uid: `dev-${match[1]}`, isAnonymous: false, email: null } : null
  }

  private emit() {
    const user = this.user()
    this.listeners.forEach((listener) => listener(user))
  }

  onChange(listener: (user: SessionUser | null) => void) {
    this.listeners.add(listener)
    void this.loaded.then(() => {
      if (this.listeners.has(listener)) listener(this.user())
    })
    return () => {
      this.listeners.delete(listener)
    }
  }

  async getToken() {
    await this.loaded
    return this.token
  }

  async signInDemo(name: string, admin: boolean) {
    const clean = name
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_-]/g, '')
      .slice(0, 40)
    if (clean.length < 3) throw new Error('Use at least 3 letters or digits.')
    await this.loaded // the stored session must not overwrite a newer sign-in
    this.token = `dev-${admin ? 'admin-' : ''}${clean}`
    await AsyncStorage.setItem(DEV_KEY, this.token)
    this.emit()
  }

  async signOut() {
    await this.loaded
    this.token = null
    await AsyncStorage.removeItem(DEV_KEY).catch(() => undefined)
    this.emit()
  }
}

// ----- Firebase -----------------------------------------------------------------------------------
type FirebaseAuthModule = typeof import('firebase/auth')

export class FirebaseAuthClient implements AuthClient {
  readonly mode = 'firebase' as const
  private loaded: Promise<{ auth: import('firebase/auth').Auth; sdk: FirebaseAuthModule }> | null = null

  private load() {
    this.loaded ??= (async () => {
      const { initializeApp } = await import('firebase/app')
      const sdk = await import('firebase/auth')
      const app = initializeApp({
        apiKey: process.env.EXPO_PUBLIC_FIREBASE_API_KEY,
        authDomain: process.env.EXPO_PUBLIC_FIREBASE_AUTH_DOMAIN,
        projectId: process.env.EXPO_PUBLIC_FIREBASE_PROJECT_ID,
        appId: process.env.EXPO_PUBLIC_FIREBASE_APP_ID,
      })
      // Metro resolves firebase/auth to its React Native build, which keeps the session in
      // AsyncStorage (the web typings do not declare getReactNativePersistence).
      const rn = sdk as unknown as { getReactNativePersistence?: (storage: typeof AsyncStorage) => unknown }
      const auth = rn.getReactNativePersistence
        ? sdk.initializeAuth(app, {
            persistence: rn.getReactNativePersistence(AsyncStorage) as import('firebase/auth').Persistence,
          })
        : sdk.getAuth(app)
      const emulator = process.env.EXPO_PUBLIC_FIREBASE_AUTH_EMULATOR_HOST
      if (emulator) sdk.connectAuthEmulator(auth, `http://${emulator}`, { disableWarnings: true })
      return { auth, sdk }
    })()
    return this.loaded
  }

  onChange(listener: (user: SessionUser | null) => void) {
    let unsubscribe: (() => void) | null = null
    let cancelled = false
    void this.load().then(({ auth, sdk }) => {
      if (cancelled) return
      unsubscribe = sdk.onIdTokenChanged(auth, (user) =>
        listener(user ? { uid: user.uid, isAnonymous: user.isAnonymous, email: user.email } : null),
      )
    })
    return () => {
      cancelled = true
      unsubscribe?.()
    }
  }

  async getToken() {
    const { auth } = await this.load()
    return auth.currentUser ? auth.currentUser.getIdToken() : null
  }

  async signInAnonymously() {
    const { auth, sdk } = await this.load()
    await sdk.signInAnonymously(auth)
  }

  async signInWithEmail(email: string, password: string, create: boolean) {
    const { auth, sdk } = await this.load()
    if (create) await sdk.createUserWithEmailAndPassword(auth, email, password)
    else await sdk.signInWithEmailAndPassword(auth, email, password)
  }

  async signOut() {
    const { auth, sdk } = await this.load()
    await sdk.signOut(auth)
  }
}

export class NoAuthClient implements AuthClient {
  readonly mode = 'off' as const
  onChange(listener: (user: SessionUser | null) => void) {
    listener(null)
    return () => undefined
  }
  async getToken() {
    return null
  }
  async signOut() {}
}

export function createAuthClient(mode: AuthMode = authMode()): AuthClient {
  if (mode === 'firebase') return new FirebaseAuthClient()
  if (mode === 'dev') return new DevAuthClient()
  return new NoAuthClient()
}

/** Human-readable sign-in errors (never shows raw provider messages). */
export function authErrorMessage(error: unknown): string {
  const code = typeof error === 'object' && error && 'code' in error ? String(error.code) : ''
  const known: Record<string, string> = {
    'auth/invalid-credential': 'Wrong e-mail or password.',
    'auth/wrong-password': 'Wrong e-mail or password.',
    'auth/user-not-found': 'Wrong e-mail or password.',
    'auth/email-already-in-use': 'An account with this e-mail already exists. Sign in instead.',
    'auth/weak-password': 'Use a password with at least 6 characters.',
    'auth/invalid-email': 'Enter a valid e-mail address.',
    'auth/network-request-failed': 'Cannot reach the sign-in service. Check your connection.',
    'auth/too-many-requests': 'Too many attempts. Please wait a moment.',
    'auth/operation-not-allowed': 'This sign-in method is not enabled for this project.',
    'auth/admin-restricted-operation': 'This sign-in method is not enabled for this project.',
  }
  if (known[code]) return known[code]
  if (error instanceof Error && !code) return error.message
  return 'Sign-in failed. Please try again.'
}
