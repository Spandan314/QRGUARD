import { useFocusEffect, useRouter } from 'expo-router'
import { useCallback, useState } from 'react'
import { Pressable, Text, View } from 'react-native'
import { RiskBadge } from '../../components/RiskBadge'
import { ActionButton, Card, ErrorBanner, Screen, styles as ui } from '../../components/ui'
import { colors } from '../../constants/theme'
import { useAuth } from '../../context/AuthContext'
import { api, ApiError } from '../../services/api'
import type { HistoryItem } from '../../types/api'
import { confirmAction } from '../../utils/confirm'

const TYPE_LABEL: Record<HistoryItem['input_type'], string> = {
  url: 'Link',
  message: 'Message',
  screenshot: 'Screenshot',
  qr_camera: 'QR (camera)',
  qr_image: 'QR (photo)',
}

function describeTarget(item: HistoryItem): string {
  const t = item.target
  if (t.kind === 'url') return t.domain ?? 'link'
  if (t.kind === 'upi') return `UPI payment${t.payee_domain ? ` (${t.payee_domain})` : ''}`
  if (t.kind === 'message' || t.kind === 'screenshot') {
    return `${t.length ?? '?'} characters, ${t.url_count ?? 0} link${t.url_count === 1 ? '' : 's'}`
  }
  return `QR code (${t.kind})`
}

function Row({ item, onDelete }: { item: HistoryItem; onDelete: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  return (
    <Card>
      <Pressable accessibilityRole="button" accessibilityLabel={`${item.risk_level} ${describeTarget(item)}`} onPress={() => setOpen(!open)} testID="history-item">
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
          <RiskBadge level={item.risk_level} />
          <Text style={ui.mono}>{item.risk_score}/100</Text>
        </View>
        <Text style={[ui.body, { marginTop: 6 }]}>
          {TYPE_LABEL[item.input_type]} · {describeTarget(item)}
        </Text>
        <Text style={ui.small}>{new Date(item.created_at).toLocaleString()}</Text>
      </Pressable>
      {open ? (
        <View style={{ gap: 4 }}>
          <Text style={ui.small}>
            {item.verification.status === 'VERIFIED' ? '🔎 Verified' : '❔ Unverified'} · confidence {item.confidence.toLowerCase()}
          </Text>
          {item.indicators.map((indicator, index) => (
            <Text key={`${indicator.id}-${index}`} style={ui.body}>
              • {indicator.title ?? indicator.id}
            </Text>
          ))}
          {item.recommended_action ? <Text style={ui.small}>{item.recommended_action}</Text> : null}
        </View>
      ) : null}
      <ActionButton label="Delete" variant="secondary" onPress={() => onDelete(item.id)} />
    </Card>
  )
}

export default function HistoryScreen() {
  const { user, ready } = useAuth()
  const router = useRouter()
  const [items, setItems] = useState<HistoryItem[]>([])
  const [cursor, setCursor] = useState<string | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const load = useCallback(async (next: string | null) => {
    try {
      const page = await api.history(next)
      setItems((current) => (next ? [...current, ...page.items] : page.items))
      setCursor(page.next_cursor)
      setLoaded(true)
      setError(null)
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }, [])

  // Reload whenever the tab gets focus (new results may have been saved).
  useFocusEffect(
    useCallback(() => {
      if (user) void load(null)
    }, [user, load]),
  )

  async function remove(id: string) {
    try {
      await api.deleteHistoryItem(id)
      setItems((current) => current.filter((item) => item.id !== id))
    } catch (caught) {
      if (caught instanceof ApiError) setError(caught)
    }
  }

  function removeAll() {
    confirmAction('Delete all saved results?', 'This cannot be undone.', 'Delete all', () =>
      void api.deleteAllHistory().then(
        () => {
          setItems([])
          setCursor(null)
        },
        (caught: unknown) => caught instanceof ApiError && setError(caught),
      ),
    )
  }

  if (!ready) return <Screen><Text style={ui.body}>Loading…</Text></Screen>
  if (!user) {
    return (
      <Screen intro="Sign in to keep a private history of your checks. Only verdicts are saved.">
        <ActionButton label="Sign in" onPress={() => router.push('/settings')} />
      </Screen>
    )
  }

  return (
    <Screen intro="Only verdicts are saved – never your messages, screenshots, QR contents or full links. Results are removed after 90 days.">
      {error ? <ErrorBanner error={error} /> : null}
      {loaded && items.length === 0 ? <Text style={ui.body}>No saved results yet.</Text> : null}
      {items.map((item) => (
        <Row key={item.id} item={item} onDelete={(id) => void remove(id)} />
      ))}
      {cursor ? <ActionButton label="Load more" variant="secondary" onPress={() => void load(cursor)} /> : null}
      {items.length > 0 ? (
        <Pressable accessibilityRole="button" onPress={removeAll} style={{ alignSelf: 'center', padding: 12 }}>
          <Text style={{ color: colors.danger, fontWeight: '700' }}>Delete all</Text>
        </Pressable>
      ) : null}
    </Screen>
  )
}
