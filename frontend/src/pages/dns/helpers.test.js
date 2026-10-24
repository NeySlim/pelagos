// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { mapLimit } from './helpers'

describe('mapLimit', () => {
  it('keeps the order and never exceeds the limit', async () => {
    let inFlight = 0
    let peak = 0
    const out = await mapLimit([5, 1, 4, 2, 3, 0], 2, async (n) => {
      inFlight += 1
      peak = Math.max(peak, inFlight)
      await new Promise((r) => setTimeout(r, n))
      inFlight -= 1
      return n * 10
    })
    expect(out).toEqual([50, 10, 40, 20, 30, 0])
    expect(peak).toBe(2)
  })

  it('handles an empty list', async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([])
  })
})
