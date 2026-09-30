import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { loadEnv } from 'vite'
import { defineConfig, type ViteUserConfig } from 'vitest/config'
import { deployProblems } from './src/deployChecks'

const config: ViteUserConfig = {
  plugins: [react(), tailwindcss()],
  server: { port: 5173 },
  build: { sourcemap: false },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/main.tsx', 'src/test/**', 'src/**/*.test.{ts,tsx}', 'src/vite-env.d.ts'],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
}

export default defineConfig(({ command, mode }) => {
  // Vercel sets VERCEL=1 during its builds: refuse settings that only make sense locally.
  if (command === 'build' && process.env.VERCEL) {
    const problems = deployProblems({ ...loadEnv(mode, process.cwd(), 'VITE_'), ...process.env })
    if (problems.length) throw new Error(`Hosted build refused:\n- ${problems.join('\n- ')}`)
  }
  return config
})
