// The QRGUARD mark, drawn on a 120 x 120 grid with 4-unit QR modules. Every brand asset is built
// from these functions, so the web logo, favicon and app icons always match.

export const PALETTE = {
  shieldTop: '#0f766e', // teal-700, the existing brand colour
  shieldBottom: '#134e4a', // teal-900
  module: '#ffffff',
  scan: '#fbbf24', // amber-400: the scan line
  ink: '#0f172a', // slate-900
  iconBackground: '#f0fdfa', // teal-50
}

const SHIELD = 'M60 6 104 20v36c0 28-18 48-44 58C34 104 16 84 16 56V20Z'

// A QR finder pattern: a 7-module ring around a 3-module core.
const finder = (x, y) => `M${x} ${y}h28v28h-28zM${x + 4} ${y + 4}v20h20v-20zM${x + 8} ${y + 8}h12v12h-12z`
const FINDERS = finder(30, 24) + finder(62, 24) + finder(30, 62)
const DATA = 'M62 62h8v8h-8zM74 62h4v4h-4zM82 62h8v4h-8zM66 74h4v8h-4zM74 70h8v8h-8zM86 74h4v8h-4zM62 82h4v4h-4zM74 82h4v4h-4z'
const SCAN = 'M22.5 54.5h75a2.5 2.5 0 0 1 0 5h-75a2.5 2.5 0 0 1 0-5z'

const svg = (viewBox, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}">${body}</svg>\n`

const gradient = (id) =>
  `<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">` +
  `<stop offset="0" stop-color="${PALETTE.shieldTop}"/><stop offset="1" stop-color="${PALETTE.shieldBottom}"/>` +
  `</linearGradient></defs>`

/** Full-colour mark. `detail: false` drops the small data modules for tiny sizes (favicons). */
export function markBody({ detail = true, id = 'qrguard-shield' } = {}) {
  return (
    gradient(id) +
    `<path fill="url(#${id})" d="${SHIELD}"/>` +
    `<path fill="${PALETTE.module}" fill-rule="evenodd" d="${FINDERS}${detail ? DATA : ''}"/>` +
    `<path fill="${PALETTE.scan}" d="${SCAN}"/>`
  )
}

export const mark = (options) => svg('0 0 120 120', markBody(options))

/** One colour: the shield with the QR and scan line cut out (Android themed icons). */
export const monoBody = (colour = '#ffffff') =>
  `<path fill="${colour}" fill-rule="evenodd" d="${SHIELD}${FINDERS}${DATA}${SCAN}"/>`

export const monoMark = (colour) => svg('0 0 120 120', monoBody(colour))

/** The mark centred on a square canvas at `scale` of its size, on an optional background. */
export function placed(body, { scale, background }) {
  const size = 120 / scale
  const offset = (size - 120) / 2
  const bg = background ? `<rect x="${-offset}" y="${-offset}" width="${size}" height="${size}" fill="${background}"/>` : ''
  return svg(`${-offset} ${-offset} ${size} ${size}`, bg + body)
}
