// SPDX-License-Identifier: Apache-2.0
// Cumulative counters that grow like real traffic, so rates derived by the UI move:
// the rate is a mean modulated by a few sines, and the counter is its exact integral
// since the mock started (no state, any read order).

const STARTED = Date.now()
const WAVES = [
  [0.34, 180],
  [0.2, 47],
  [0.12, 13],
]

function seedOf(text) {
  let h = 2166136261
  for (const ch of String(text)) {
    h ^= ch.codePointAt(0)
    h = Math.imul(h, 16777619)
  }
  return ((h >>> 0) % 6283) / 1000
}

// Counter value at `now` for a series named `key` with `base` at start and `mean` per second.
export function liveCount(key, base, mean, now = Date.now()) {
  const t = Math.max(0, (now - STARTED) / 1000)
  const p = seedOf(key)
  let integral = t
  WAVES.forEach(([amp, period], i) => {
    const w = (2 * Math.PI) / period
    const phase = p * (i + 1)
    integral += (amp / w) * (Math.cos(phase) - Math.cos(w * t + phase))
  })
  return Math.round(base + mean * integral)
}

// Scales every counter of `counters` (name -> [base, mean per second]) for one node.
export function liveCounters(nodeKey, counters, now = Date.now()) {
  return Object.fromEntries(Object.entries(counters).map(([name, [base, mean]]) => [name, liveCount(`${nodeKey}/${name}`, base, mean, now)]))
}
