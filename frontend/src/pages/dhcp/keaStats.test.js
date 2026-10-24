// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { poolHistory, subnetUtilization } from './keaStats'

describe('subnet utilization', () => {
  it('uses addresses, then NAs, then prefixes', () => {
    expect(subnetUtilization({ counters: { 'total-addresses': 20, 'assigned-addresses': 5 } })).toEqual({ assigned: 5, total: 20, percent: 25 })
    expect(subnetUtilization({ counters: { 'total-nas': 4, 'assigned-nas': 1, 'total-pds': 2, 'assigned-pds': 2 } }).percent).toBe(25)
    expect(subnetUtilization({ counters: { 'total-pds': 2, 'assigned-pds': 2 } }).percent).toBe(100)
  })

  it('has no figure without a total', () => {
    expect(subnetUtilization({ counters: { 'total-addresses': 0, 'assigned-addresses': 0 } })).toBeNull()
    expect(subnetUtilization({})).toBeNull()
  })
})

describe('pool history', () => {
  it('sums the pools per timestamp and sorts by time', () => {
    const series = [
      { key: { pool: 'a' }, points: [['2026-10-24T11:00:00Z', 5, 10], ['2026-10-24T10:00:00Z', 2, 10]] },
      { key: { pool: 'b' }, points: [['2026-10-24T10:00:00Z', 8, 30], ['2026-10-24T11:00:00Z', 15, 30], ['junk', 1, 1]] },
    ]
    expect(poolHistory(series)).toEqual([
      { t: Date.parse('2026-10-24T10:00:00Z'), value: 25 },
      { t: Date.parse('2026-10-24T11:00:00Z'), value: 50 },
    ])
    expect(poolHistory(undefined)).toEqual([])
  })
})
