// SPDX-License-Identifier: Apache-2.0
// Pure helpers behind the motion v2 components: odometer alignment, ruler ticks,
// procedure progress, Poisson spacing of link ticks, and the FLIP row helper.

const SCALE = { k: 1e3, K: 1e3, M: 1e6, G: 1e9 }

// Numeric value of a label, its unit prefix included ("1.24 k/s" is 1240).
const numeric = (text) => {
  const m = String(text).replace(/,/g, '').match(/(-?\d+(?:\.\d+)?)\s*([kKMG])?/)
  return m ? Number(m[1]) * (SCALE[m[2]] || 1) : null
}

// Direction of a change: explicit, else by numeric value, else up.
export function rollDirection(previous, next, explicit) {
  if (explicit === 'up' || explicit === 'down') return explicit
  const [a, b] = [numeric(previous), numeric(next)]
  return a !== null && b !== null && b < a ? 'down' : 'up'
}

// Right-aligns the old characters against the new ones; a new leading character rolls in
// from a blank. Returns one { char, from } cell per character of `next`.
export function rollCells(previous, next) {
  const chars = [...next]
  const olds = [...previous]
  const pad = Math.max(0, chars.length - olds.length)
  const aligned = Array(pad).fill('').concat(olds.slice(Math.max(0, olds.length - chars.length)))
  return chars.map((char, i) => ({ char, from: aligned[i] }))
}

// Round tick values (1, 2 or 5 times a power of ten) from 0 to `max`, about `count` of them.
export function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0]
  const raw = max / count
  const power = 10 ** Math.floor(Math.log10(raw))
  const step = [1, 2, 5, 10].map((m) => m * power).find((s) => s >= raw) || 10 * power
  const ticks = []
  for (let v = 0; v <= max + step * 1e-9; v += step) ticks.push(Number(v.toPrecision(12)))
  return ticks
}

export const STEP_STATES = ['pending', 'running', 'done', 'failed', 'reverted']

// Share of a procedure behind the cursor: done items, plus half of a running one.
export function progressOf(items) {
  if (!items.length) return 0
  const done = items.filter((i) => i.state === 'done').length
  const running = items.some((i) => i.state === 'running') ? 0.5 : 0
  return Math.min(1, (done + running) / items.length)
}

export const PULSE_MS = 600
export const MAX_TICKS = 4

// Milliseconds to the next arrival of a Poisson process at `rate` per second.
export function poissonGap(rate, random = Math.random) {
  if (!(rate > 0)) return Infinity
  return (-Math.log(1 - random()) / rate) * 1000
}

// Glides rows from `dy` px away to their place on the spring (the Invert and Play steps
// of FLIP). `moves` is [[row, dy]]; one forced layout for all of them.
export function glideRows(moves) {
  for (const [r, dy] of moves) {
    r.classList.remove('fx-flip')
    r.style.transform = `translateY(${dy}px)`
  }
  if (moves.length) moves[0][0].getBoundingClientRect()
  for (const [r] of moves) {
    r.classList.add('fx-flip')
    r.style.transform = ''
    r.addEventListener('transitionend', () => r.classList.remove('fx-flip'), { once: true })
  }
  return moves.length
}

// True when the keys both lists share appear in another order (a sort, a divergence
// resolved), not when rows merely come or go.
export function orderChanged(previous, next) {
  const nextSet = new Set(next)
  const prevSet = new Set(previous)
  const a = previous.filter((k) => nextSet.has(k))
  const b = next.filter((k) => prevSet.has(k))
  return a.length > 1 && a.some((k, i) => k !== b[i])
}

// FLIP: measure `rows`, run `mutate` (which must update the DOM synchronously, e.g. through
// flushSync), then glide every moved row from its old place on the spring. Reads are
// batched before writes. Below full motion it only mutates. Returns how many rows moved.
export function flipRows(rows, mutate, level = typeof document !== 'undefined' ? document.documentElement.dataset.motion : 'full') {
  const list = [...rows]
  if (level !== 'full' || list.length === 0) {
    mutate()
    return 0
  }
  const first = new Map(list.map((r) => [r, r.getBoundingClientRect().top]))
  mutate()
  const moves = []
  for (const r of list) {
    if (!r.isConnected) continue
    const dy = first.get(r) - r.getBoundingClientRect().top
    if (Math.abs(dy) >= 0.5) moves.push([r, dy])
  }
  return glideRows(moves)
}

const STRIP = { pad: 8, top: 16, bottom: 14, ruler: 22 }

// Geometry of a strip: points right-aligned over `slots` slots.
export function stripGeometry(points, { width, height, slots, kind }) {
  const series = points.slice(-slots)
  const step = Math.max(1, (width - STRIP.pad * 2 - (kind === 'line' ? STRIP.ruler : 0)) / Math.max(1, slots - 1))
  const offset = slots - series.length
  const max = Math.max(0, ...series.map((p) => p.v)) * 1.15 || 1
  const x = (i) => STRIP.pad + (i + offset) * step
  const y = (v) => STRIP.top + (height - STRIP.top - STRIP.bottom) * (1 - Math.max(0, v) / max)
  return { series, step, offset, max, x, y }
}
