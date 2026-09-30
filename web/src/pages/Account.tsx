import { useState, type FormEvent } from 'react'
import { Link } from 'react-router'
import { buttonClass, inputClass } from '../components/CheckPage'
import { ErrorAlert } from '../components/ErrorAlert'
import { useAuth } from '../context/AuthContext'
import { api, ApiError } from '../services/api'
import { authErrorMessage } from '../services/auth'

/** Sign-in methods are optional per mode; the UI only offers the ones the mode has. */
function required<T extends (...args: never[]) => Promise<void>>(method: T | undefined): T {
  if (!method) throw new Error('This sign-in method is not available.')
  return method
}

function SignIn() {
  const { client } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [demoName, setDemoName] = useState('')
  const [demoAdmin, setDemoAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function attempt(action: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await action()
    } catch (caught) {
      setError(authErrorMessage(caught))
    } finally {
      setBusy(false)
    }
  }

  if (client.mode === 'off') {
    return (
      <p className="text-slate-600 dark:text-slate-300">
        Sign-in is not configured for this installation. All checks still work without an account.
      </p>
    )
  }

  return (
    <div className="space-y-6">
      {client.mode === 'firebase' ? (
        <>
          <section className="space-y-2">
            <h2 className="text-xl font-semibold">Quick start</h2>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              A private, anonymous account on this device. No e-mail needed.
            </p>
            <button type="button" className={buttonClass} disabled={busy} onClick={() => void attempt(() => required(client.signInAnonymously?.bind(client))())}>
              Continue without an e-mail
            </button>
          </section>
          <form
            className="space-y-2"
            onSubmit={(event: FormEvent) => {
              event.preventDefault()
              void attempt(() => required(client.signInWithEmail?.bind(client))(email.trim(), password, false))
            }}
          >
            <h2 className="text-xl font-semibold">E-mail and password</h2>
            <label className="block">
              <span className="font-medium">E-mail</span>
              <input className={inputClass} type="email" autoComplete="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </label>
            <label className="block">
              <span className="font-medium">Password</span>
              <input
                className={inputClass}
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
            <div className="flex flex-wrap gap-2">
              <button type="submit" className={buttonClass} disabled={busy || !email || !password}>
                Sign in
              </button>
              <button
                type="button"
                className="min-h-11 rounded-lg border border-teal-700 px-4 font-semibold text-teal-700 dark:text-teal-300"
                disabled={busy || !email || !password}
                onClick={() => void attempt(() => required(client.signInWithEmail?.bind(client))(email.trim(), password, true))}
              >
                Create account
              </button>
            </div>
          </form>
        </>
      ) : (
        <form
          className="space-y-2"
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            void attempt(() => required(client.signInDemo?.bind(client))(demoName, demoAdmin))
          }}
        >
          <h2 className="text-xl font-semibold">Demo sign-in</h2>
          <p className="text-sm text-amber-800 dark:text-amber-300">
            Demo mode (no Firebase project): the server must run with AUTH_DEV_TOKENS=true. Not available in production.
          </p>
          <label className="block">
            <span className="font-medium">Demo user name</span>
            <input className={inputClass} value={demoName} onChange={(e) => setDemoName(e.target.value)} placeholder="alice" />
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={demoAdmin} onChange={(e) => setDemoAdmin(e.target.checked)} />
            Sign in as an administrator
          </label>
          <button type="submit" className={buttonClass} disabled={busy || demoName.trim().length < 3}>
            Sign in
          </button>
        </form>
      )}
      {error ? (
        <p role="alert" className="text-sm text-red-700 dark:text-red-300">
          {error}
        </p>
      ) : null}
    </div>
  )
}

function Profile() {
  const { client, user, profile, refreshProfile } = useAuth()
  const [error, setError] = useState<ApiError | null>(null)
  const [message, setMessage] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  async function toggle(save: boolean) {
    setError(null)
    try {
      await api.updateMe(save)
      await refreshProfile()
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  async function deleteEverything() {
    setError(null)
    try {
      const result = await api.deleteMe()
      setMessage(`Deleted ${result.deleted_scans} saved result(s). Your account data has been removed.`)
      await client.signOut()
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  return (
    <div className="space-y-6">
      <section className="space-y-1">
        <h2 className="text-xl font-semibold">Signed in</h2>
        <p className="text-sm text-slate-600 dark:text-slate-300">
          {user?.email ?? (user?.isAnonymous ? 'Anonymous account on this device' : user?.uid)}
          {profile?.admin ? ' · administrator' : ''}
        </p>
      </section>
      {profile ? (
        <section className="space-y-2">
          <h2 className="text-xl font-semibold">Privacy</h2>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={profile.save_history} onChange={(e) => void toggle(e.target.checked)} />
            Offer to save my results to my history
          </label>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Only the verdict is saved (level, score, reasons, the website's domain). Messages, screenshots, QR contents and
            full links are never stored. Saved results are deleted automatically after {profile.history_retention_days} days.{' '}
            <Link to="/history" className="text-teal-700 underline dark:text-teal-400">
              View my history
            </Link>
          </p>
          {confirmDelete ? (
            <div className="space-y-2 rounded-lg border border-red-300 p-3" role="alertdialog" aria-label="Confirm deletion">
              <p className="font-medium">Delete all my saved results, reports link and account? This cannot be undone.</p>
              <div className="flex gap-2">
                <button type="button" className="min-h-11 rounded-lg bg-red-700 px-4 font-semibold text-white" onClick={() => void deleteEverything()}>
                  Yes, delete everything
                </button>
                <button type="button" className="min-h-11 px-4" onClick={() => setConfirmDelete(false)}>
                  Cancel
                </button>
              </div>
            </div>
          ) : (
            <button type="button" className="min-h-11 rounded-lg border border-red-700 px-4 font-semibold text-red-700 dark:text-red-300" onClick={() => setConfirmDelete(true)}>
              Delete my data
            </button>
          )}
        </section>
      ) : (
        <p className="text-sm text-slate-600 dark:text-slate-300">History is not available on this server right now.</p>
      )}
      <button type="button" className={buttonClass} onClick={() => void client.signOut()}>
        Sign out
      </button>
      {message ? <p role="status">{message}</p> : null}
      {error ? <ErrorAlert error={error} /> : null}
    </div>
  )
}

export default function Account() {
  const { user, ready } = useAuth()
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Account &amp; privacy</h1>
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-900">
        {!ready ? <p role="status">Loading…</p> : user ? <Profile /> : <SignIn />}
      </div>
    </div>
  )
}
