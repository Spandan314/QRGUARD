// Draws the inspection pass on a <canvas> for "Save as image" (no image library). It mirrors the
// on-screen ticket: paper card, field grid, perforated divider with notches, pass number and the
// rotated stamp. The paper colours are fixed; the page behind the notches follows the theme.
import type { PassData, Stamp } from './pass'

const INK = '#1f1b14'
const INK_MUTED = '#5c5345'
const PAPER = '#f5efe4'
const BRAND = '#0a7a5e'
const PERFORATION = '#cfc6b5'
export const STAMP_INK: Record<Stamp, string> = {
  DENIED: '#b42318',
  CAUTION: '#8a4b00',
  CLEARED: '#0a7a5e',
  'NOT VERIFIED': '#5c5345',
}

const DISPLAY = "'Space Grotesk Variable', 'Inter Variable', sans-serif"
const SANS = "'Inter Variable', system-ui, sans-serif"
const MONO = "'JetBrains Mono Variable', ui-monospace, monospace"

const WIDTH = 380 // CSS px; drawn at 3x
const SCALE = 3
const MARGIN = 20
const PAD = 22

/** Splits a word wider than the line, preferring a break after "." or "-" (long hosts). */
function breakWord(ctx: CanvasRenderingContext2D, word: string, maxWidth: number): string[] {
  const parts: string[] = []
  let rest = word
  while (ctx.measureText(rest).width > maxWidth && rest.length > 1) {
    let end = rest.length - 1
    while (end > 1 && ctx.measureText(rest.slice(0, end)).width > maxWidth) end--
    const soft = Math.max(rest.lastIndexOf('.', end - 1), rest.lastIndexOf('-', end - 1))
    if (soft > end / 2) end = soft + 1
    parts.push(rest.slice(0, end))
    rest = rest.slice(end)
  }
  return [...parts, rest]
}

function wrap(ctx: CanvasRenderingContext2D, text: string, maxWidth: number): string[] {
  const lines: string[] = []
  let line = ''
  for (const word of text.split(/\s+/).flatMap((w) => breakWord(ctx, w, maxWidth))) {
    const next = line ? `${line} ${word}` : word
    if (ctx.measureText(next).width <= maxWidth || !line) {
      line = next
    } else {
      lines.push(line)
      line = word
    }
  }
  if (line) lines.push(line)
  return lines
}

function spaced(ctx: CanvasRenderingContext2D, text: string, x: number, y: number, spacing: number, align: 'left' | 'right' = 'left') {
  const width = [...text].reduce((w, c) => w + ctx.measureText(c).width + spacing, -spacing)
  let cx = align === 'right' ? x - width : x
  for (const c of text) {
    ctx.fillText(c, cx, y)
    cx += ctx.measureText(c).width + spacing
  }
}

/** Lays the pass out on `ctx` and returns the height it needs (CSS px). */
function layout(ctx: CanvasRenderingContext2D, pass: PassData, page: string): number {
  const left = MARGIN
  const inner = WIDTH - 2 * MARGIN - 2 * PAD
  let y = MARGIN + PAD
  ctx.textBaseline = 'top'

  ctx.font = `700 15px ${DISPLAY}`
  ctx.fillStyle = INK
  ctx.fillText('QR', left + PAD, y)
  ctx.fillStyle = BRAND
  ctx.fillText('GUARD', left + PAD + ctx.measureText('QR').width, y)
  ctx.font = `500 10px ${MONO}`
  ctx.fillStyle = INK_MUTED
  spaced(ctx, 'INSPECTION PASS', WIDTH - MARGIN - PAD, y + 3, 1.4, 'right')
  y += 34

  ctx.font = `700 25px ${DISPLAY}`
  ctx.fillStyle = INK
  const titleLines = wrap(ctx, pass.title, inner)
  for (const line of titleLines) {
    ctx.fillText(line, left + PAD, y)
    y += 30
  }
  y += 12

  const colWidth = (inner - 16) / 2
  for (let i = 0; i < pass.fields.length; i += 2) {
    let rowHeight = 0
    for (const [col, field] of pass.fields.slice(i, i + 2).entries()) {
      const x = left + PAD + col * (colWidth + 16)
      ctx.font = `500 10px ${MONO}`
      ctx.fillStyle = INK_MUTED
      spaced(ctx, field.label, x, y, 1.4)
      ctx.font = `600 14px ${SANS}`
      ctx.fillStyle = INK
      const lines = wrap(ctx, field.value, colWidth)
      lines.forEach((line, n) => ctx.fillText(line, x, y + 16 + n * 19))
      rowHeight = Math.max(rowHeight, 16 + lines.length * 19)
    }
    y += rowHeight + 12
  }
  y += 8

  // perforation with notches in the page colour
  const divider = y + 12
  ctx.strokeStyle = PERFORATION
  ctx.lineWidth = 2
  ctx.setLineDash([6, 5])
  ctx.beginPath()
  ctx.moveTo(left + 18, divider)
  ctx.lineTo(WIDTH - MARGIN - 18, divider)
  ctx.stroke()
  ctx.setLineDash([])
  ctx.fillStyle = page
  for (const cx of [left, WIDTH - MARGIN]) {
    ctx.beginPath()
    ctx.arc(cx, divider, 12, 0, Math.PI * 2)
    ctx.fill()
  }
  y += 24 + 14

  // stamp measurements first: it sits bottom-right, beside the pass number
  ctx.font = `700 ${pass.stamp.length > 8 ? 16 : 21}px ${DISPLAY}`
  const label = pass.stamp
  const textWidth = [...label].reduce((w, c) => w + ctx.measureText(c).width + 2.5, -2.5)
  const boxW = textWidth + 22
  const boxH = 36
  const textMax = inner - boxW - 14
  const bottomTop = y

  ctx.font = `500 11px ${MONO}`
  ctx.fillStyle = INK_MUTED
  spaced(ctx, `PASS NO. ${pass.number}`, left + PAD, y, 1.1)
  y += 20
  ctx.font = `400 13px ${SANS}`
  ctx.fillStyle = INK
  for (const line of wrap(ctx, 'Inspected on the QRGUARD server, not on the device that scanned it.', textMax)) {
    ctx.fillText(line, left + PAD, y)
    y += 19
  }
  y = Math.max(y, bottomTop + boxH + 8)

  ctx.save()
  ctx.font = `700 ${pass.stamp.length > 8 ? 16 : 21}px ${DISPLAY}`
  ctx.translate(WIDTH - MARGIN - PAD - boxW / 2, (bottomTop + y) / 2)
  ctx.rotate((-12 * Math.PI) / 180)
  ctx.strokeStyle = STAMP_INK[label]
  ctx.lineWidth = 4
  ctx.beginPath()
  ctx.roundRect(-boxW / 2, -boxH / 2, boxW, boxH, 10)
  ctx.stroke()
  ctx.fillStyle = STAMP_INK[label]
  ctx.textBaseline = 'middle'
  spaced(ctx, label, -textWidth / 2, 1, 2.5)
  ctx.restore()
  y += PAD - 4

  return y + MARGIN
}

async function fontsReady() {
  try {
    await Promise.all([`700 16px ${DISPLAY}`, `600 16px ${SANS}`, `500 16px ${MONO}`].map((f) => document.fonts.load(f)))
  } catch {
    // fall back to the system fonts named in each stack
  }
}

/** Renders the pass to a PNG blob, or null when this browser cannot draw it. */
export async function renderPassImage(pass: PassData): Promise<Blob | null> {
  await fontsReady()
  const page = getComputedStyle(document.documentElement).getPropertyValue('--bg').trim() || '#0a0f14'
  const measure = document.createElement('canvas').getContext('2d')
  if (!measure) return null
  const height = layout(measure, pass, page)

  const canvas = document.createElement('canvas')
  canvas.width = WIDTH * SCALE
  canvas.height = Math.ceil(height * SCALE)
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  ctx.scale(SCALE, SCALE)
  ctx.fillStyle = page
  ctx.fillRect(0, 0, WIDTH, height)
  ctx.fillStyle = PAPER
  ctx.beginPath()
  ctx.roundRect(MARGIN, MARGIN, WIDTH - 2 * MARGIN, height - 2 * MARGIN, 18)
  ctx.fill()
  layout(ctx, pass, page)
  return new Promise((resolve) => canvas.toBlob(resolve, 'image/png'))
}
