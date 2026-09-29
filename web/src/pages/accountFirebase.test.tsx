import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { AuthClient, SessionUser } from '../services/auth'
import { jsonResponse } from '../test/fixtures'
import { renderRoute } from '../test/renderRoute'

/** A Firebase-mode client double (the real Firebase SDK is covered in firebaseAuth.test.ts). */
function firebaseLikeClient() {
  let listener: ((user: SessionUser | null) => void) | null = null
  const set = (user: SessionUser | null) => listener?.(user)
  const client: AuthClient = {
    mode: 'firebase',
    onChange(next) {
      listener = next
      next(null)
      return () => undefined
    },
    getToken: async () => 'firebase-id-token',
    signOut: async () => set(null),
    signInAnonymously: vi.fn(async () => set({ uid: 'anon', isAnonymous: true, email: null })),
    signInWithEmail: vi.fn(async (email: string, _password: string, create: boolean) => {
      if (!create && email === 'wrong@x.in') throw Object.assign(new Error('raw'), { code: 'auth/invalid-credential' })
      set({ uid: 'mail', isAnonymous: false, email })
    }),
  }
  return client
}

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      jsonResponse({ uid: 'anon', is_anonymous: true, admin: false, save_history: true, history_retention_days: 90 }),
    ),
  )
})

describe('account page in Firebase mode', () => {
  it('signs in anonymously', async () => {
    const client = firebaseLikeClient()
    renderRoute('/account', client)
    await userEvent.click(screen.getByRole('button', { name: 'Continue without an e-mail' }))
    expect(await screen.findByText('Anonymous account on this device')).toBeInTheDocument()
    expect(client.signInAnonymously).toHaveBeenCalled()
  })

  it('creates an e-mail account and shows friendly errors', async () => {
    const client = firebaseLikeClient()
    renderRoute('/account', client)
    await userEvent.type(screen.getByLabelText('E-mail'), 'wrong@x.in')
    await userEvent.type(screen.getByLabelText('Password'), 'secret123')
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Wrong e-mail or password.')
    await userEvent.click(screen.getByRole('button', { name: 'Create account' }))
    expect(await screen.findByText('wrong@x.in')).toBeInTheDocument()
    expect(client.signInWithEmail).toHaveBeenLastCalledWith('wrong@x.in', 'secret123', true)
  })
})
