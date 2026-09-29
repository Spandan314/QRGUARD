import { useRouter } from 'expo-router'
import { Text } from 'react-native'
import { ResultView } from '../components/ResultView'
import { ActionButton, Screen, styles as ui } from '../components/ui'
import { useResult } from '../context/ResultContext'

export default function ResultScreen() {
  const { result } = useResult()
  const router = useRouter()
  if (!result) {
    return (
      <Screen>
        <Text style={ui.body}>No result to show.</Text>
        <ActionButton label="Back to home" onPress={() => router.replace('/')} />
      </Screen>
    )
  }
  return (
    <Screen>
      <ResultView result={result} />
      <ActionButton label="Check something else" variant="secondary" onPress={() => router.replace('/')} />
    </Screen>
  )
}
