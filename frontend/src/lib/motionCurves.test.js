// SPDX-License-Identifier: Apache-2.0
// Motion v2 curves: the spring overshoots by at most 1.5 % and rests by t = 1, settle never
// overshoots, the CSS tokens are these functions sampled, and ambient follows the level.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { ambientRunning, DURATIONS, easeInOut, linearEasing, normalizeAmbient, settle, spring } from './motion'

const css = readFileSync(resolve(import.meta.dirname, '../styles/motion.css'), 'utf8')
const token = (name) => css.match(new RegExp(`--${name}: (linear\\([^)]*\\));`))?.[1]
const samples = (fn) => Array.from({ length: 1001 }, (_, i) => fn(i / 1000))

describe('motion v2 curves', () => {
  it('spring starts at 0, overshoots by at most 1.5 % and rests at 1', () => {
    expect(spring(0)).toBe(0)
    expect(spring(1)).toBe(1)
    expect(spring(2)).toBe(1)
    const peak = Math.max(...samples(spring))
    expect(peak).toBeGreaterThan(1.01)
    expect(peak).toBeLessThanOrEqual(1.0152)
    expect(Math.abs(spring(0.95) - 1)).toBeLessThan(0.002)
  })

  it('settle lands without overshoot', () => {
    expect(settle(0)).toBe(0)
    expect(settle(1)).toBe(1)
    const values = samples(settle)
    expect(Math.max(...values)).toBeLessThanOrEqual(1)
    for (let i = 1; i < values.length; i += 1) expect(values[i]).toBeGreaterThanOrEqual(values[i - 1])
  })

  it('the CSS --spring and --settle tokens are the sampled functions', () => {
    expect(token('spring')).toBe(linearEasing(spring))
    expect(token('settle')).toBe(linearEasing(settle))
  })

  it('ease-in-out is symmetric and clamped', () => {
    expect(easeInOut(-1)).toBe(0)
    expect(easeInOut(0.5)).toBeCloseTo(0.5)
    expect(easeInOut(0.25) + easeInOut(0.75)).toBeCloseTo(1)
  })

  it('duration tokens match the CSS ones', () => {
    for (const [name, ms] of Object.entries(DURATIONS)) expect(css, name).toContain(`--d-${name}: ${ms}ms;`)
  })

  it('ambient moves only at full level, switched on, on a visible page', () => {
    expect(normalizeAmbient('loud')).toBe('on')
    expect(ambientRunning('full', 'on')).toBe(true)
    expect(ambientRunning('full', 'off')).toBe(false)
    expect(ambientRunning('reduced', 'on')).toBe(false)
    expect(ambientRunning('off', 'on')).toBe(false)
    expect(ambientRunning('full', 'on', true)).toBe(false)
  })
})
