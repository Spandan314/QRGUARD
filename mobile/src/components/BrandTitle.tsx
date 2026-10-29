import { StyleSheet, Text, View } from 'react-native'
import { SvgXml } from 'react-native-svg'
import { BRAND_MARK_SVG } from '../constants/brandMark'
import { colors, fonts, themedStyles } from '../constants/theme'

/** The QRGUARD logo: the shield mark (decorative) and the wordmark, which carries the name. */
export function BrandTitle() {
  return (
    <View style={styles.row}>
      <View accessible={false} importantForAccessibility="no-hide-descendants">
        <SvgXml xml={BRAND_MARK_SVG} width={28} height={28} />
      </View>
      <Text accessibilityRole="header" style={styles.word}>
        <Text style={styles.qr}>QR</Text>GUARD
      </Text>
    </View>
  )
}

const styles = themedStyles(() =>
  StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  word: { fontFamily: fonts.display, fontSize: 20, fontWeight: '800', letterSpacing: -0.3, color: colors.brand },
  qr: { fontFamily: fonts.sans, color: colors.text },
}),
)
