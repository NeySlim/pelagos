// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { countUpAllowed, interpolate, loopsAllowed, normalizeAnimations, resolveMotionLevel, transitionsAllowed } from './motion'

describe('motion levels', () => {
  it('normalizes unknown preferences to full', () => {
    expect(normalizeAnimations(undefined)).toBe('full')
    expect(normalizeAnimations('wild')).toBe('full')
    expect(normalizeAnimations('off')).toBe('off')
  })

  it('lets the system reduced-motion setting lower the level, never raise it', () => {
    expect(resolveMotionLevel('full', false)).toBe('full')
    expect(resolveMotionLevel('full', true)).toBe('reduced')
    expect(resolveMotionLevel('reduced', false)).toBe('reduced')
    expect(resolveMotionLevel('off', true)).toBe('off')
    expect(resolveMotionLevel('off', false)).toBe('off')
  })

  it('runs loops only at full level on a visible page', () => {
    expect(loopsAllowed('full')).toBe(true)
    expect(loopsAllowed('full', true)).toBe(false)
    expect(loopsAllowed('reduced')).toBe(false)
    expect(loopsAllowed('off')).toBe(false)
  })

  it('keeps transitions at reduced level and counters at full only', () => {
    expect(transitionsAllowed('reduced')).toBe(true)
    expect(transitionsAllowed('off')).toBe(false)
    expect(countUpAllowed('full')).toBe(true)
    expect(countUpAllowed('reduced')).toBe(false)
  })

  it('interpolates with an ease-out and lands on the target', () => {
    expect(interpolate(0, 100, 0, 1000)).toBe(0)
    const mid = interpolate(0, 100, 500, 1000)
    expect(mid).toBeGreaterThan(50)
    expect(mid).toBeLessThan(100)
    expect(interpolate(0, 100, 1000, 1000)).toBe(100)
    expect(interpolate(10, 5, 2000, 1000)).toBe(5)
  })
})
