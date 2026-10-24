// SPDX-License-Identifier: Apache-2.0
// Motion levels: the user preference (full, reduced, off) combined with the system
// reduced-motion setting. The system setting can only lower the level, never raise it.

export const ANIMATION_LEVELS = ['full', 'reduced', 'off']
export const DEFAULT_ANIMATIONS = 'full'

export function normalizeAnimations(value) {
  return ANIMATION_LEVELS.includes(value) ? value : DEFAULT_ANIMATIONS
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

// Enter transitions and counters: full plays them, reduced keeps a short fade, off skips them.
export function transitionsAllowed(level) {
  return level !== 'off'
}

export function countUpAllowed(level) {
  return level === 'full'
}

export function easeOutCubic(t) {
  const x = Math.min(1, Math.max(0, t))
  return 1 - (1 - x) ** 3
}

// Value shown by a counter going from `from` to `to` after `elapsed` of `duration` ms.
export function interpolate(from, to, elapsed, duration) {
  if (duration <= 0 || elapsed >= duration) return to
  return from + (to - from) * easeOutCubic(elapsed / duration)
}
