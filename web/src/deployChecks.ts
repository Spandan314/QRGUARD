/**
 * Build-time checks for hosted (Vercel) builds. A hosted web app must call the deployed HTTPS
 * backend and use real Firebase sign-in; these settings are fine locally but broken or unsafe
 * once published, so the build stops with a clear message instead of deploying them.
 */
export function deployProblems(env: Record<string, string | undefined>): string[] {
  const problems: string[] = []
  const api = env.VITE_API_BASE_URL ?? ''
  if (!api.startsWith('https://')) {
    problems.push('VITE_API_BASE_URL must be the https:// URL of the deployed backend')
  }
  if (env.VITE_AUTH_MODE === 'dev') {
    problems.push('VITE_AUTH_MODE=dev (demo accounts) must not be used for a hosted build')
  }
  if (env.VITE_FIREBASE_AUTH_EMULATOR_HOST) {
    problems.push('VITE_FIREBASE_AUTH_EMULATOR_HOST must not be set for a hosted build')
  }
  return problems
}
