// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { mapLimit, catalogRow } from './helpers'

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

describe('catalogRow', () => {
  it('reads default primaries and member count from the backend shape', () => {
    const row = catalogRow({
      zone: 'catalog.example.lan.',
      statement: '{ zone "other.example" default-primaries { 192.0.2.9; }; zone "catalog.example.lan" default-primaries { 192.0.2.53; 192.0.2.54; } in-memory yes; }',
      members: ['a.example.lan.', 'b.example.lan.'],
    })
    expect(row.default_primaries).toEqual(['192.0.2.53', '192.0.2.54'])
    expect(row.member_count).toBe(2)
  })

  it('keeps explicit fields', () => {
    const row = catalogRow({ zone: 'c.example.', default_primaries: ['192.0.2.1'], member_count: 4 })
    expect(row).toMatchObject({ default_primaries: ['192.0.2.1'], member_count: 4 })
  })
})
