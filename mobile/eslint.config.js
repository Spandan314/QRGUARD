// https://docs.expo.dev/guides/using-eslint/
const { defineConfig } = require('eslint/config')
const expoConfig = require('eslint-config-expo/flat')

module.exports = defineConfig([
  expoConfig,
  { ignores: ['dist/*', 'coverage/*', '.expo/*'] },
  {
    rules: {
      'no-eval': 'error',
      'no-implied-eval': 'error',
      // External links may only be opened through OpenLinkGuard (docs/architecture.md §3.3).
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'react-native', importNames: ['Linking'], message: 'Use components/OpenLinkGuard.' },
          ],
        },
      ],
    },
  },
  {
    files: ['src/components/OpenLinkGuard.tsx', 'src/**/*.test.{ts,tsx}'],
    rules: { 'no-restricted-imports': 'off' },
  },
])
