// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { formatBytes, formatCount, formatPercent, headlineCounters, topCounters, uptimeSeconds } from './instanceStats'
import { latestValue, splitStatistics, subnetColumns } from '../dhcp/keaStats'

// Intl uses narrow no-break spaces in French; compare on plain spaces.
const plain = (s) => s.replace(/[\u202f\u00a0]/g, ' ')

describe('BIND instance counters', () => {
  const stats = {
    boot_time: '2026-10-24T10:00:00Z',
    opcodes: { QUERY: 99 },
    nsstats: { Requestv4: 150020, Requestv6: 34213, Response: 184233, QryRecursion: 40210, UpdateDone: 2840, UpdateFail: 2 },
    zonestats: { XfrSuccess: 9 },
    resstats: { ValOk: 3022, ValNegOk: 120, ValFail: 1 },
  }

  it('formats counts, bytes and shares in the UI language', () => {
    expect(formatCount(184233, 'en')).toBe('184,233')
    expect(plain(formatCount(184233, 'fr'))).toBe('184 233')
    expect(formatCount(null, 'en')).toBe('-')
    expect(formatBytes(23456789, 'en')).toBe('22.4 MB')
    expect(plain(formatBytes(23456789, 'fr'))).toBe('22,4 Mo')
    expect(formatBytes(512, 'en')).toBe('512 byte')
    expect(formatPercent(0.923, 'en')).toBe('92.3%')
    expect(plain(formatPercent(0.923, 'fr'))).toBe('92,3 %')
  })

  it('sums the headline counters, falling back to the QUERY opcode', () => {
    expect(headlineCounters(stats)).toEqual({
      queries: 184233, responses: 184233, recursive: 40210, updates: 2840, updateFailures: 2,
      transfers: 9, validated: 3142, validationFailures: 1,
    })
    expect(headlineCounters({ opcodes: { QUERY: 7 } }).queries).toBe(7)
    expect(headlineCounters(null).queries).toBe(0)
  })

  it('ranks non-zero counters with their share', () => {
    const top = topCounters({ NOERROR: 75, NXDOMAIN: 25, SERVFAIL: 0 }, 5)
    expect(top).toEqual([{ name: 'NOERROR', value: 75, share: 0.75 }, { name: 'NXDOMAIN', value: 25, share: 0.25 }])
    expect(topCounters({ A: 1, B: 2, C: 3 }, 2).map((c) => c.name)).toEqual(['C', 'B'])
  })

  it('computes the uptime from the boot time', () => {
    expect(uptimeSeconds(stats, Date.parse('2026-10-24T11:00:00Z'))).toBe(3600)
    expect(uptimeSeconds({}, 0)).toBeNull()
  })
})

describe('Kea statistics', () => {
  const stamp = '2026-10-24 10:00:00.000000'
  const statistics = {
    'pkt4-received': [[120, stamp], [100, stamp]],
    'subnet[1].pool[0].total-addresses': [[100, stamp]],
    'subnet[1].pool[1].total-addresses': [[50, stamp]],
    'subnet[1].pool[0].assigned-addresses': [[10, stamp]],
    'subnet[2].total-addresses': [[30, stamp]],
    'subnet[2].pool[0].total-addresses': [[25, stamp]],
    'pkt4-ack-sent': [[90, stamp]],
  }

  it('reads the newest sample', () => {
    expect(latestValue([[5, stamp], [4, stamp]])).toBe(5)
    expect(latestValue(7)).toBe(7)
    expect(latestValue([])).toBeNull()
  })

  it('splits server counters from subnet counters, subnet level winning over pool sums', () => {
    const { global, subnets } = splitStatistics(statistics)
    expect(global).toEqual([{ name: 'pkt4-ack-sent', value: 90 }, { name: 'pkt4-received', value: 120 }])
    expect(subnets).toEqual([
      { id: 1, counters: { 'total-addresses': 150, 'assigned-addresses': 10 } },
      { id: 2, counters: { 'total-addresses': 30 } },
    ])
    expect(subnetColumns(subnets)).toEqual(['total-addresses', 'assigned-addresses'])
  })
})
