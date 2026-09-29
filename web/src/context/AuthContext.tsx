import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, setTokenProvider } from '../services/api'
import { createAuthClient, type AuthClient, type SessionUser } from '../services/auth'
import type { Profile } from '../types/api'

interface AuthState {
  client: AuthClient
  user: SessionUser | null
  /** Server-side profile (settings, admin flag); null when signed out or history is unavailable. */
  profile: Profile | null
  ready: boolean
  refreshProfile: () => Promise<void>
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({ children, client: given }: { children: ReactNode; client?: AuthClient }) {
  const [client] = useState<AuthClient>(() => given ?? createAuthClient())
  const [user, setUser] = useState<SessionUser | null>(null)
  const [profile, setProfile] = useState<Profile | null>(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    setTokenProvider(() => client.getToken())
    return client.onChange((next) => {
      setUser(next)
      setReady(true)
      if (!next) setProfile(null)
    })
  }, [client])

  const refreshProfile = useCallback(async () => {
    try {
      const next = await api.me()
      setProfile(next)
    } catch {
      setProfile(null) // e.g. history not configured on the server: signed in, but no profile
    }
  }, [])

  useEffect(() => {
    if (!user) return
    let active = true
    api.me().then(
      (next) => active && setProfile(next),
      () => active && setProfile(null), // e.g. history not configured on the server
    )
    return () => {
      active = false
    }
  }, [user])

  const value = useMemo(
    () => ({ client, user, profile, ready, refreshProfile }),
    [client, user, profile, ready, refreshProfile],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/** For components that also render outside the provider (e.g. in isolated tests). */
export function useOptionalAuth(): AuthState | null {
  return useContext(AuthContext)
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext)
  if (!value) throw new Error('useAuth must be used inside AuthProvider')
  return value
}
