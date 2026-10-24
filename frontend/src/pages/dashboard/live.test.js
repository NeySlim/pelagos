// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { advance, appendPoint, combine, dhcpCounters, dnsCounters, emptySource, keaCounter, latest, prune, sampleTime, share, summarizeLive } from './live'
import { liveTargets } from './useLiveRates'

const sample = (t, total, parts = {}) => ({ t: t * 1000, counters: { total, parts } })

describe('counter extraction', () => {
  it('reads queries from the QUERY opcode, else the request counters', () => {
    expect(dnsCounters({ opcodes: { QUERY: 50 }, rcodes: { NOERROR: 40, NXDOMAIN: 10 } })).toEqual({
      total: 50,
      parts: { NOERROR: 40, NXDOMAIN: 10, SERVFAIL: 0, REFUSED: 0 },
    })
    expect(dnsCounters({ nsstats: { Requestv4: 7, Requestv6: 3 } }).total).toBe(10)
    expect(dnsCounters(null)).toBeNull()
  })

  it('reads the newest Kea sample and the family counters', () => {
    const st = { 'pkt4-ack-sent': [[12, 'b'], [10, 'a']], 'pkt4-received': [[30, 'b']], 'pkt6-reply-sent': [[5, 'x']] }
    expect(keaCounter(st, 'pkt4-ack-sent')).toBe(12)
    expect(keaCounter(st, 'missing')).toBeNull()
    expect(dhcpCounters({ statistics: st }, 'v4')).toEqual({ total: 12, parts: { received: 30 } })
    expect(dhcpCounters({ statistics: st }, 'v6')).toEqual({ total: 5, parts: { received: 0 } })
    expect(dhcpCounters({ statistics: {} }, 'v4')).toBeNull()
  })

  it('stamps a sample with collected_at when it parses', () => {
    expect(sampleTime({ collected_at: '2026-10-24T10:00:00Z' }, 5)).toBe(Date.parse('2026-10-24T10:00:00Z'))
    expect(sampleTime({ collected_at: 'junk' }, 5)).toBe(5)
  })
})

describe('rates', () => {
  it('needs two samples and divides by the elapsed time', () => {
    let s = advance(emptySource(), sample(0, 100, { NOERROR: 90 }))
    expect(s.points).toEqual([])
    s = advance(s, sample(4, 140, { NOERROR: 126 }))
    expect(s.points).toEqual([{ t: 4000, v: 10 }])
    expect(s.parts.NOERROR).toEqual([{ t: 4000, v: 9 }])
  })

  it('ignores the same snapshot twice and rebases after a counter reset', () => {
    let s = advance(advance(emptySource(), sample(0, 100)), sample(2, 120))
    expect(advance(s, sample(2, 120))).toBe(s)
    s = advance(s, sample(4, 5))
    expect(s.points).toHaveLength(1)
    expect(s.last.counters.total).toBe(5)
    s = advance(s, sample(6, 25))
    expect(latest(s.points)).toBe(10)
  })

  it('keeps at most `capacity` points', () => {
    let points = []
    for (let i = 0; i < 10; i += 1) points = appendPoint(points, { t: i, v: i }, 4)
    expect(points.map((p) => p.v)).toEqual([6, 7, 8, 9])
  })

  it('sums series aligned on their newest point', () => {
    const a = [{ t: 1, v: 1 }, { t: 2, v: 2 }, { t: 3, v: 3 }]
    const b = [{ t: 2, v: 10 }, { t: 3, v: 20 }]
    expect(combine([a, b, undefined])).toEqual([{ t: 1, v: 1 }, { t: 2, v: 12 }, { t: 3, v: 23 }])
    expect(combine([])).toEqual([])
  })

  it('computes the share of a part in the newest rates', () => {
    expect(share({ NOERROR: [{ t: 1, v: 75 }], NXDOMAIN: [{ t: 1, v: 25 }] }, 'NXDOMAIN')).toBe(25)
    expect(share({}, 'NXDOMAIN')).toBeNull()
  })

  it('drops points older than the window', () => {
    const s = { last: { t: 0, counters: { total: 1 } }, points: [{ t: 0, v: 1 }, { t: 9000, v: 2 }], parts: { A: [{ t: 0, v: 1 }] } }
    const out = prune(s, 10000, 5000)
    expect(out.points).toEqual([{ t: 9000, v: 2 }])
    expect(out.parts.A).toEqual([])
    expect(out.last).toBeNull()
  })
})

describe('dashboard targets and view', () => {
  const node = (id, status = 'online', modules) => ({ peer: { id, name: id, modules }, status })

  it('follows the engines each online node runs', () => {
    const targets = liveTargets([node('a', 'online', { bind: true, kea4: true, kea6: false }), node('b', 'offline'), node('c', 'online', { bind: false, kea4: false, kea6: true })])
    expect(targets.map((t) => t.key)).toEqual(['dns:a', 'dhcp:v4:a', 'dhcp:v6:c'])
    expect(liveTargets([node('a')], { dns: false, dhcp: false })).toEqual([])
  })

  it('sums the nodes and keeps each node rate', () => {
    const targets = [
      { key: 'dns:a', kind: 'dns', node: 'a' },
      { key: 'dns:b', kind: 'dns', node: 'b' },
      { key: 'dhcp:v4:a', kind: 'dhcp', node: 'a' },
    ]
    const src = (v) => ({ last: null, points: [{ t: 1, v }], parts: { NXDOMAIN: [{ t: 1, v: v / 10 }] } })
    const view = summarizeLive(targets, { 'dns:a': src(100), 'dns:b': src(50), 'dhcp:v4:a': src(4) })
    expect(view.dns.current).toBe(150)
    expect(view.dns.byNode).toEqual({ a: 100, b: 50 })
    expect(view.dns.rcodes.NXDOMAIN).toEqual([{ t: 1, v: 15 }])
    expect(view.dhcp.current).toBe(4)
    expect(summarizeLive([], {}).dns.enabled).toBe(false)
  })
})
