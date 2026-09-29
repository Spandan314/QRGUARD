import { useState } from 'react'
import { Switch, Text, TextInput, View } from 'react-native'
import { BackendStatus } from '../../components/BackendStatus'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { API_BASE_URL } from '../../constants/config'
import { useAuth } from '../../context/AuthContext'
import { api, ApiError } from '../../services/api'
import { authErrorMessage } from '../../services/auth'
import { confirmAction } from '../../utils/confirm'

function SignIn() {
  const { client } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [demoName, setDemoName] = useState('')
  const [demoAdmin, setDemoAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function attempt(action: (() => Promise<void>) | undefined) {
    if (!action) return
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
    return <Text style={ui.body}>Sign-in is not configured for this installation. All checks still work without an account.</Text>
  }
  if (client.mode === 'dev') {
    return (
      <View style={{ gap: 8 }}>
        <Text style={ui.label}>Demo sign-in</Text>
        <Text style={ui.small}>Demo mode: the server must run with AUTH_DEV_TOKENS=true. Not available in production.</Text>
        <TextInput
          accessibilityLabel="Demo user name"
          style={ui.input}
          value={demoName}
          onChangeText={setDemoName}
          autoCapitalize="none"
          placeholder="alice"
        />
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <Switch accessibilityLabel="Sign in as an administrator" value={demoAdmin} onValueChange={setDemoAdmin} />
          <Text style={ui.small}>Administrator</Text>
        </View>
        <ActionButton
          label="Sign in"
          loading={busy}
          disabled={demoName.trim().length < 3}
          onPress={() => void attempt(client.signInDemo && (() => client.signInDemo!(demoName, demoAdmin)))}
        />
        {error ? <Text style={ui.errorText} accessibilityRole="alert">{error}</Text> : null}
      </View>
    )
  }
  return (
    <View style={{ gap: 8 }}>
      <Text style={ui.label}>Quick start</Text>
      <Text style={ui.small}>A private, anonymous account on this phone. No e-mail needed.</Text>
      <ActionButton
        label="Continue without an e-mail"
        loading={busy}
        onPress={() => void attempt(client.signInAnonymously && (() => client.signInAnonymously!()))}
      />
      <Text style={[ui.label, { marginTop: 12 }]}>E-mail and password</Text>
      <TextInput accessibilityLabel="E-mail" style={ui.input} value={email} onChangeText={setEmail} autoCapitalize="none" keyboardType="email-address" />
      <TextInput accessibilityLabel="Password" style={ui.input} value={password} onChangeText={setPassword} secureTextEntry />
      <ActionButton
        label="Sign in"
        disabled={busy || !email || !password}
        onPress={() => void attempt(client.signInWithEmail && (() => client.signInWithEmail!(email.trim(), password, false)))}
      />
      <ActionButton
        label="Create account"
        variant="secondary"
        disabled={busy || !email || !password}
        onPress={() => void attempt(client.signInWithEmail && (() => client.signInWithEmail!(email.trim(), password, true)))}
      />
      {error ? <Text style={ui.errorText} accessibilityRole="alert">{error}</Text> : null}
    </View>
  )
}

function Account() {
  const { client, user, profile, refreshProfile } = useAuth()
  const [error, setError] = useState<ApiError | null>(null)

  async function toggle(save: boolean) {
    try {
      await api.updateMe(save)
      await refreshProfile()
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  function deleteEverything() {
    confirmAction(
      'Delete my data?',
      'All saved results and your account data will be removed. This cannot be undone.',
      'Delete everything',
      () =>
        void api.deleteMe().then(
          () => void client.signOut(),
          (caught: unknown) => caught instanceof ApiError && setError(caught),
        ),
    )
  }

  return (
    <View style={{ gap: 10 }}>
      <Text style={ui.label}>Signed in</Text>
      <Text style={ui.small}>
        {user?.email ?? (user?.isAnonymous ? 'Anonymous account on this phone' : user?.uid)}
        {profile?.admin ? ' · administrator' : ''}
      </Text>
      {profile ? (
        <>
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
            <Switch
              accessibilityLabel="Offer to save my results to my history"
              value={profile.save_history}
              onValueChange={(value) => void toggle(value)}
            />
            <Text style={[ui.body, { flex: 1 }]}>Offer to save my results to my history</Text>
          </View>
          <Text style={ui.small}>
            Only the verdict is saved (level, score, reasons and the domain of a link) – never messages, screenshots, QR
            contents or full links. Saved results are deleted after {profile.history_retention_days} days.
          </Text>
          <ActionButton label="Delete my data" variant="danger" onPress={deleteEverything} />
        </>
      ) : (
        <Text style={ui.small}>History is not available on this server right now.</Text>
      )}
      <ActionButton label="Sign out" variant="secondary" onPress={() => void client.signOut()} />
      {error ? <ErrorBanner error={error} /> : null}
    </View>
  )
}

export default function Settings() {
  const { user, ready } = useAuth()
  return (
    <Screen>
      <Card>{!ready ? <Text style={ui.body}>Loading…</Text> : user ? <Account /> : <SignIn />}</Card>
      <Card>
        <Text style={ui.label}>Server</Text>
        <Text style={ui.mono}>{API_BASE_URL}</Text>
        <BackendStatus />
      </Card>
      <Card>
        <Text style={ui.label}>How QRGUARD decides</Text>
        <Text style={ui.body}>
          Every result lists the warning signs found and the points each added. The level comes only from the score
          (SAFE 0–29, SUSPICIOUS 30–59, MALICIOUS 60–100). Verification is shown separately and never changes the
          score. Not being on a threat list never makes something look safer.
        </Text>
      </Card>
      <Card>
        <Text style={ui.label}>Privacy</Text>
        <Text style={ui.body}>
          Messages, screenshots and QR contents are sent to the QRGUARD server only to be checked; they are not
          stored or logged. Links are never opened for you. QR codes you make are created on your phone. The camera
          is used only while you scan. With history on, only the verdict is saved.
        </Text>
      </Card>
      <Card>
        <Text style={ui.label}>Report fraud (India)</Text>
        <Text style={ui.body}>Call 1930 (cyber-fraud helpline) or report at cybercrime.gov.in. Tell your bank at once.</Text>
      </Card>
      <Text style={[ui.small, { textAlign: 'center' }]}>
        QRGUARD gives an automated security assessment, not a guarantee.
      </Text>
    </Screen>
  )
}
