import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { loadEnv } from 'vite'
import { defineConfig, type ViteUserConfig } from 'vitest/config'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import type { Plugin } from 'vite'
import { parseOfficialDomains } from './src/utils/brandsYaml'
import { deployProblems } from './src/deployChecks'

// Brands' official domains, read at build time from the backend's brand list (read-only), so
// "Open the real site instead" can link to the official site. A missing file fails the build.
const BRANDS_FILE = fileURLToPath(new URL('../backend/app/data/brands.yaml', import.meta.url))
function officialDomains(): Plugin {
  const id = 'virtual:official-domains'
  return {
    name: 'qrguard-official-domains',
    resolveId: (source) => (source === id ? `\0${id}` : undefined),
    load(loaded) {
      if (loaded !== `\0${id}`) return undefined
      this.addWatchFile(BRANDS_FILE)
      const domains = parseOfficialDomains(readFileSync(BRANDS_FILE, 'utf8'))
      if (Object.keys(domains).length === 0) throw new Error(`No official domains found in ${BRANDS_FILE}`)
      return `export default ${JSON.stringify(domains)}`
    },
  }
}

const config: ViteUserConfig = {
  plugins: [react(), tailwindcss(), officialDomains()],
  server: { port: 5173 },
  build: {
    sourcemap: false,
    // Never inline fonts as data: URIs: the Content-Security-Policy only allows same-origin
    // fonts, and every font must be a normal file served by this site.
    assetsInlineLimit: (file) => (/\.(woff2?|ttf|otf)$/.test(file) ? false : undefined),
  },
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
