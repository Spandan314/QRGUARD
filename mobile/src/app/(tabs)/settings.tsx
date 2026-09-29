import { Text } from 'react-native'
import { BackendStatus } from '../../components/BackendStatus'
import { Card, Screen, styles as ui } from '../../components/ui'
import { API_BASE_URL } from '../../constants/config'

export default function Settings() {
  return (
    <Screen>
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
          is used only while you scan.
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
