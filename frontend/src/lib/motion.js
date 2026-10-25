// SPDX-License-Identifier: Apache-2.0
// Motion levels: the user preference (full, reduced, off) combined with the system
// reduced-motion setting. The system setting can only lower the level, never raise it.
// Also the motion v2 curves for JS (canvas): the CSS tokens in styles/effects.css are
// the same functions sampled as linear() strings.

export const ANIMATION_LEVELS = ['full', 'reduced', 'off']
export const DEFAULT_ANIMATIONS = 'full'
export const AMBIENT_MODES = ['on', 'off']
export const DEFAULT_AMBIENT = 'on'

// Duration tokens in ms, mirrored by --d-* in styles/effects.css.
export const DURATIONS = Object.freeze({ instant: 70, fast: 110, quick: 150, base: 200, panel: 240, page: 260, slow: 400, moment: 600 })

export function normalizeAnimations(value) {
  return ANIMATION_LEVELS.includes(value) ? value : DEFAULT_ANIMATIONS
}

export function normalizeAmbient(value) {
  return AMBIENT_MODES.includes(value) ? value : DEFAULT_AMBIENT
}

export function resolveMotionLevel(preference, systemReduced = false) {
  const level = normalizeAnimations(preference)
  if (level === 'off') return 'off'
  if (level === 'reduced' || systemReduced) return 'reduced'
  return 'full'
}

// Looping effects (sweeps, pulses, flowing dashes) run only at full level on a visible page.
export function loopsAllowed(level, hidden = false) {
  return level === 'full' && !hidden
}

// Ambient backgrounds move only at full level, when switched on, on a visible page.
export function ambientRunning(level, ambient = DEFAULT_AMBIENT, hidden = false) {
  return loopsAllowed(level, hidden) && normalizeAmbient(ambient) === 'on'
}

// Enter transitions and counters: full plays them, reduced keeps a short fade, off skips them.
export function transitionsAllowed(level) {
  return level !== 'off'
}

export function countUpAllowed(level) {
  return level === 'full'
}

const clamp01 = (t) => Math.min(1, Math.max(0, t))

export function easeOutCubic(t) {
  const x = clamp01(t)
  return 1 - (1 - x) ** 3
}

export const easeOut = easeOutCubic

export function easeInOut(t) {
  const x = clamp01(t)
  return x < 0.5 ? 4 * x * x * x : 1 - (-2 * x + 2) ** 3 / 2
}

// Underdamped spring over normalized time: zeta 0.8 overshoots by 1.5 % and rests by t = 1
// (300 ms in CSS). For things that move and stop: cursors, ink, rows, playheads.
export function spring(t, zeta = 0.8, omega = 9) {
  const x = clamp01(t)
  if (x >= 1) return 1
  const root = Math.sqrt(1 - zeta * zeta)
  const wd = omega * root
  return 1 - Math.exp(-zeta * omega * x) * (Math.cos(wd * x) + (zeta / root) * Math.sin(wd * x))
}

// Critically damped spring: no overshoot. For things that land: ticks, markers, digits.
export function settle(t, omega = 10) {
  const x = clamp01(t)
  if (x >= 1) return 1
  return 1 - Math.exp(-omega * x) * (1 + omega * x)
}

// CSS linear() easing sampled from `fn`; the last stop is pinned to 1.
export function linearEasing(fn, samples = 24) {
  const stops = ['0']
  for (let i = 1; i < samples; i += 1) {
    const x = i / samples
    stops.push(`${Number(fn(x).toFixed(4))} ${Number((x * 100).toFixed(1))}%`)
  }
  stops.push('1')
  return `linear(${stops.join(', ')})`
}

// Value shown by a counter going from `from` to `to` after `elapsed` of `duration` ms.
export function interpolate(from, to, elapsed, duration) {
  if (duration <= 0 || elapsed >= duration) return to
  return from + (to - from) * easeOutCubic(elapsed / duration)
}
