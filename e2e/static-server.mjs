// Serves a built single-page app the way Vercel will: the security headers and SPA rewrite from
// web/vercel.json are applied, so the E2E runs under the production Content-Security-Policy and
// Permissions-Policy. The only change is that local test origins (backend, Auth emulator) are
// appended to connect-src, because the production policy only allows https://*.onrender.com.
//
//   node static-server.mjs <dir> <port> <vercel.json> "<extra connect-src origins>"
import { createReadStream, existsSync, readFileSync, statSync } from 'node:fs'
import { createServer } from 'node:http'
import { extname, join, normalize } from 'node:path'

const [dir, port, vercelFile, extraConnect = ''] = process.argv.slice(2)
const vercel = JSON.parse(readFileSync(vercelFile, 'utf8'))
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.woff2': 'font/woff2',
}

// vercel.json "source" patterns used here are simple path-to-regexp forms such as "/(.*)".
const toRegExp = (source) => new RegExp(`^${source}$`)

function headersFor(path) {
  const out = {}
  for (const rule of vercel.headers ?? []) {
    if (!toRegExp(rule.source).test(path)) continue
    for (const { key, value } of rule.headers) out[key] = value
  }
  const csp = out['Content-Security-Policy']
  if (csp && extraConnect) out['Content-Security-Policy'] = csp.replace('connect-src', `connect-src ${extraConnect}`)
  return out
}

createServer((req, res) => {
  const path = decodeURIComponent(new URL(req.url, 'http://x').pathname)
  let file = normalize(join(dir, path))
  if (!file.startsWith(normalize(dir)) || !existsSync(file) || statSync(file).isDirectory()) {
    file = join(dir, 'index.html') // SPA rewrite, as in vercel.json
  }
  res.writeHead(200, { ...headersFor(path), 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' })
  createReadStream(file).pipe(res)
}).listen(Number(port), '127.0.0.1')
