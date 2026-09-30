import { useEffect, useState } from 'react'
import { Text } from 'react-native'
import { api } from '../services/api'
import type { HealthResponse } from '../types/api'
import { styles as ui } from './ui'

type Status = { state: 'checking' } | { state: 'ok'; health: HealthResponse } | { state: 'down' }

export function BackendStatus() {
  const [status, setStatus] = useState<Status>({ state: 'checking' })
  useEffect(() => {
    const controller = new AbortController()
    api
      .health(controller.signal)
      .then((health) => setStatus({ state: 'ok', health }))
      .catch(() => {
        if (!controller.signal.aborted) setStatus({ state: 'down' })
      })
    return () => controller.abort()
  }, [])

  if (status.state === 'checking') return <Text style={ui.small}>Connecting to the QRGUARD server…</Text>
  if (status.state === 'down') {
    return (
      <Text style={ui.small} testID="backend-status">
        ⚠️ The QRGUARD server is not reachable right now (it may be starting up).
      </Text>
    )
  }
  const sources = status.health.components.threat_intel?.providers.filter((p) => p.enabled).length
  return (
    <Text style={ui.small} testID="backend-status">
      ✅ Server online · engine {status.health.engine_version}
      {sources !== undefined ? ` · ${sources} threat-intelligence source${sources === 1 ? '' : 's'} active` : ''}
    </Text>
  )
}
