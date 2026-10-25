// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  alertForPool, beatIntervalAt, beatStats, followPlayhead, formatJitter, laneMax, nearestSample, observeBeat, poolLatches, poolPressure, poolSubject, tracedPool,
  pushEvent, rulerLabel, rulerLevels, scaleBar, smoothTowards, snapToEvent, tAt, traceEventOf, visibleFrom, windowAt, xAt,
} from './trace'

const GEO = { pad: 8, plotW: 900, win: 90000 }
const NOW = 1_000_000

describe('trace mapping', () => {
  it('puts now on the right edge and now - window on the left', () => {
    expect(xAt(NOW, NOW, GEO)).toBe(908)
    expect(xAt(NOW - 90000, NOW, GEO)).toBe(8)
    expect(xAt(NOW - 45000, NOW, GEO)).toBe(458)
  })

  it('maps x back to time', () => {
    for (const t of [NOW, NOW - 1234, NOW - 90000]) expect(tAt(xAt(t, NOW, GEO), NOW, GEO)).toBeCloseTo(t, 6)
  })

  it('interpolates the window over 400 ms ease-in-out', () => {
    const anim = { from: 90000, to: 30000, t0: 100 }
    expect(windowAt(anim, 100).win).toBe(90000)
    expect(windowAt(anim, 300).win).toBeCloseTo(60000, 0)
    const end = windowAt(anim, 500)
    expect(end).toEqual({ win: 30000, done: true })
    // ease-in-out: slow start
    expect(windowAt(anim, 140).win).toBeGreaterThan(89000)
    expect(windowAt({ from: 90000, to: 90000, t0: 0 }, 50)).toEqual({ win: 90000, done: true })
  })

  it('smooths the scale exponentially and starts at the target', () => {
    expect(smoothTowards(undefined, 100, 16)).toBe(100)
    const one = smoothTowards(0, 100, 220)
    expect(one).toBeCloseTo(100 * (1 - Math.exp(-1)), 6)
    expect(smoothTowards(50, 100, 10000)).toBeCloseTo(100, 6)
  })

  it('gives a lane 15 % headroom', () => {
    expect(laneMax([{ v: 10 }, { v: 100 }])).toBeCloseTo(115)
    expect(laneMax([])).toBe(1)
  })

  it('draws from the sample just before the left edge', () => {
    const s = [10, 20, 30, 40].map((t) => ({ t, v: 0 }))
    expect(visibleFrom(s, 25)).toBe(1)
    expect(visibleFrom(s, 5)).toBe(0)
    expect(visibleFrom(s, 50)).toBe(3)
  })

  it('reads the nearest sample', () => {
    const s = [1000, 2000, 4000, 8000].map((t, i) => ({ t, v: i }))
    expect(nearestSample(s, 2900).t).toBe(2000)
    expect(nearestSample(s, 3100).t).toBe(4000)
    expect(nearestSample(s, 99999).t).toBe(8000)
    expect(nearestSample(s, -5).t).toBe(1000)
    expect(nearestSample([], 5)).toBeNull()
  })
})

describe('playhead', () => {
  const events = [{ t: NOW - 45000, kind: 'plan' }, { t: NOW - 10000, kind: 'alert' }]

  it('snaps to a marker within 7 px', () => {
    const x = xAt(NOW - 45000, NOW, GEO)
    expect(snapToEvent(events, x + 6, NOW, GEO).event.kind).toBe('plan')
    expect(snapToEvent(events, x + 6, NOW, GEO).x).toBeCloseTo(x)
    expect(snapToEvent(events, x - 6.9, NOW, GEO)).not.toBeNull()
    expect(snapToEvent(events, x + 7.5, NOW, GEO)).toBeNull()
  })

  it('follows the pointer over 40 ms, or at once below full', () => {
    expect(followPlayhead(null, 100, 16)).toBe(100)
    expect(followPlayhead(0, 100, 40)).toBeCloseTo(100 * (1 - Math.exp(-1)))
    expect(followPlayhead(0, 100, 16, false)).toBe(100)
  })
})

describe('ruler and scale bar', () => {
  it('labels the readable sets and crossfades a coarser one away', () => {
    const at90 = Object.fromEntries(rulerLevels(900, 90000).map((l) => [l.step, l]))
    // 10 s ticks are 100 px apart: labelled. 2 s ticks are 20 px: ticks only.
    expect(at90[10000].label).toBeGreaterThan(0.9)
    expect(at90[2000].label).toBe(0)
    expect(at90[2000].tick).toBe(1)
    expect(at90[30000].label).toBe(0)
    expect(at90[1000]).toBeDefined()
    const at5m = Object.fromEntries(rulerLevels(900, 300000).map((l) => [l.step, l]))
    expect(at5m[1000]).toBeUndefined()
    expect(at5m[30000].label).toBeGreaterThan(0.9)
    expect(at5m[10000].label).toBe(0)
  })

  it('writes ages as seconds, minutes or hours', () => {
    expect(rulerLabel(10000)).toBe('-10 s')
    expect(rulerLabel(90000)).toBe('-90 s')
    expect(rulerLabel(120000)).toBe('-2 min')
    expect(rulerLabel(3600000)).toBe('-1 h')
  })

  it('rescales the bar with the window and switches its unit', () => {
    expect(scaleBar(90000, 900)).toEqual({ span: 10000, label: '10 s', ratio: 100 / 60 })
    expect(scaleBar(30000, 900).ratio).toBeCloseTo(5)
    const five = scaleBar(300000, 900)
    expect(five.label).toBe('1 min')
    expect(five.ratio).toBeCloseTo(3)
  })
})

describe('heartbeats', () => {
  it('measures a beat from the partner age and narrows it with each observation', () => {
    let beats = observeBeat([], { collectedAt: 10_400, age: 3 })
    expect(beats).toEqual([{ t: 6_900, lo: 6_400, hi: 7_400 }])
    beats = observeBeat(beats, { collectedAt: 11_100, age: 4 })
    expect(beats).toHaveLength(1)
    expect(beats[0].lo).toBe(6_400)
    expect(beats[0].hi).toBe(7_100)
    // Same observation twice: same list.
    expect(observeBeat(beats, { collectedAt: 11_100, age: 4 })).toBe(beats)
    // A later beat.
    beats = observeBeat(beats, { collectedAt: 18_000, age: 1 })
    expect(beats).toHaveLength(2)
    expect(beats[0].t).toBe(16_500)
    // A stale snapshot of the older beat adds nothing.
    expect(observeBeat(beats, { collectedAt: 9_000, age: 1 })).toBe(beats)
    expect(observeBeat(beats, { collectedAt: 9_000, age: null })).toBe(beats)
  })

  it('reports the mean interval and the jitter, ignoring outage gaps', () => {
    const beats = [40_020, 30_000, 20_010, 9_990, 0].map((t) => ({ t }))
    const st = beatStats(beats)
    expect(st.mean).toBeCloseTo(10_005)
    expect(st.sd).toBeGreaterThan(0)
    expect(st.sd).toBeLessThan(30)
    const gap = [{ t: 100_000 }, { t: 30_000 }, { t: 20_000 }, { t: 10_000 }]
    expect(beatStats(gap).mean).toBe(10_000)
    expect(beatStats([{ t: 1 }])).toBeNull()
    // An outage under twice the median still spans no heartbeat once its end is marked.
    const failback = [{ t: 50_000 }, { t: 40_000, afterGap: true }, { t: 22_000 }, { t: 12_000 }, { t: 2_000 }]
    expect(beatStats(failback)).toMatchObject({ mean: 10_000, sd: 0, count: 3 })
    expect(formatJitter(312.4)).toBe('±312 ms')
    expect(formatJitter(4715)).toBe('±4.7 s')
    expect(formatJitter(NaN)).toBe('')
    expect(beatIntervalAt(beats, 25_000)).toBe(10_020)
    expect(beatIntervalAt(beats, -1)).toBeNull()
  })
})

describe('events lane', () => {
  it('maps WebSocket messages to markers', () => {
    const ts = '2026-10-25T10:00:00Z'
    expect(traceEventOf({ topic: 'plans', event: 'applied', ts, data: { plan_id: 'PLAN0000001234' } })).toMatchObject({ kind: 'plan', t: Date.parse(ts), params: { plan: '001234' } })
    expect(traceEventOf({ topic: 'plans', event: 'rolled_back', ts, data: {} }).kind).toBe('rb')
    expect(traceEventOf({ topic: 'alerts', event: 'opened', ts, data: { kind: 'pool_full' } }).kind).toBe('alert')
    expect(traceEventOf({ topic: 'alerts', event: 'resolved', ts, data: { kind: 'pool_full' } }).kind).toBe('ok')
    expect(traceEventOf({ topic: 'alerts', event: 'resolved', ts, data: { kind: 'serial_divergence', subject: 'zone:x' } }).kind).toBe('axfr')
    expect(traceEventOf({ topic: 'alerts', event: 'acked', ts, data: {} })).toBeNull()
    expect(traceEventOf({ topic: 'ha', event: 'state', ts, data: { state: 'partner-down', server_name: 'ns1' } }).kind).toBe('ha')
    expect(traceEventOf({ topic: 'system', event: 'replication', ts, data: { version: 43 } }).params.version).toBe(43)
    expect(traceEventOf({ topic: 'leases', event: 'summary', ts, data: {} })).toBeNull()
  })

  it('keeps events sorted, without duplicates or old ones', () => {
    let ev = pushEvent([], { t: 2000, kind: 'plan', id: 'a' }, 2000)
    ev = pushEvent(ev, { t: 1000, kind: 'alert', id: 'b' }, 2000)
    expect(ev.map((e) => e.t)).toEqual([1000, 2000])
    expect(pushEvent(ev, { t: 2000, kind: 'plan', id: 'a' }, 2000)).toBe(ev)
    expect(pushEvent(ev, { t: 900000, kind: 'ok' }, 900000)).toHaveLength(1)
  })
})

describe('pool pressure', () => {
  it('turns a series into percent samples', () => {
    expect(poolPressure([[10, 5, 20], [20, 19, 20], [30, 1, 0]])).toEqual([{ t: 10000, v: 25 }, { t: 20000, v: 95 }])
  })

  it('latches an alert where it opened and releases it where it resolved', () => {
    const samples = [{ t: 1000, v: 80 }, { t: 2000, v: 100 }, { t: 3000, v: 86 }]
    const latches = poolLatches([
      { id: 'a', first_seen: new Date(2000).toISOString(), resolved_at: new Date(3000).toISOString() },
      { id: 'b', first_seen: new Date(2100).toISOString() },
    ], samples)
    expect(latches.map((l) => [l.t, l.state, l.v])).toEqual([[2000, 'held', 100], [2100, 'open', 100], [3000, 'released', 86]])
  })

  it('matches pool alerts by their subject', () => {
    const pool = { engine: 'kea4', subnet_id: 3, pool: '192.0.2.200 - 192.0.2.219', node_id: 'N1' }
    expect(alertForPool({ kind: 'pool_full', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', node_id: 'N1' }, pool)).toBe(true)
    expect(alertForPool({ kind: 'pool_full', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', node_id: 'N2' }, pool)).toBe(false)
    expect(alertForPool({ kind: 'ptr_mismatch', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219' }, pool)).toBe(false)
  })
})

describe('traced pool', () => {
  const pool = (subnet_id, name, percent) => ({ node_id: 'N1', engine: 'kea4', subnet_id, pool: name, percent })
  const hottest = pool(1, '192.0.2.10 - 192.0.2.19', 95)
  const guest = pool(3, '192.0.2.200 - 192.0.2.219', 90)
  const pools = [hottest, guest]
  const alert = (extra) => ({ id: 'a', kind: 'pool_full', node_id: 'N1', subject: poolSubject(guest), first_seen: new Date(1000).toISOString(), ...extra })

  it('follows the latest pool alert, open or resolved within the window, else the hottest pool', () => {
    expect(tracedPool(pools, [], [], 5000)).toBe(hottest)
    expect(tracedPool(pools, [alert()], [], 5000)).toBe(guest)
    // Resolved: the trace stays on its pool to show the latches.
    expect(tracedPool(pools, [], [alert({ t: 4000 })], 5000, 3600000)).toBe(guest)
    expect(tracedPool(pools, [], [alert({ t: 4000 })], 4000 + 3600001, 3600000)).toBe(hottest)
    expect(tracedPool(pools, [alert({ subject: 'kea4:subnet:9:pool:x' })], [], 5000)).toBe(hottest)
    expect(tracedPool([], [], [])).toBeNull()
  })
})
