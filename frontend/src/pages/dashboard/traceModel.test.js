// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach } from 'vitest'
import { clockOffset, haFamilies, heartbeatOf, heartbeatReadout, linkOf, nodeEngines, topology, traceLanes } from './traceModel'
import { beatStats } from '../../lib/trace'
import { isHaTransition, observePoolAlerts, poolAlertsSeen, observeHa, observeNodeVersion, observeZoneSerials, resetClusterSignals } from '../../hooks/useClusterSignals'

const node = (id, name, self, extra = {}) => ({ peer: { id, name }, is_self: self, status: 'online', config_version: 42, ...extra })
const LABELS = { dns: 'DNS queries', dnsUnit: 'queries/s', dhcp: 'DHCP leases', dhcpUnit: 'leases/s', hb: 'HA heartbeat', events: 'Events' }
const FORMAT = { dns: String, dhcp: String }

describe('trace topology', () => {
  it('puts this node first and counts the peers beyond the second', () => {
    const t = topology([node('b', 'ns2', false), node('a', 'ns1', true), node('c', 'ns3', false)])
    expect(t.self.peer.name).toBe('ns1')
    expect(t.peer.peer.name).toBe('ns2')
    expect(t.more).toBe(1)
    expect(topology([])).toEqual({ self: null, peer: null, more: 0 })
  })

  it('lists the engines a node runs, DHCPv6 only with its module', () => {
    const n = { peer: { modules: { bind: true, kea4: true, kea6: true, d2: false } } }
    expect(nodeEngines(n).map((e) => e.label)).toEqual(['BIND', 'DHCPv4', 'DHCPv6'])
    expect(nodeEngines(n, { dhcpv6: false }).map((e) => e.label)).toEqual(['BIND', 'DHCPv4'])
    expect(nodeEngines({ peer: {} })).toHaveLength(4)
  })

  it('tells a link in sync, behind or down', () => {
    const a = node('a', 'ns1', true, { config_version: 43 })
    expect(linkOf(a, node('b', 'ns2', false, { config_version: 43 }))).toMatchObject({ state: 'ok', status: 'inSync' })
    expect(linkOf(a, node('b', 'ns2', false, { config_version: 41 }))).toMatchObject({ state: 'ok', status: 'behind', behind: 2 })
    expect(linkOf(a, node('b', 'ns2', false, { status: 'offline' }))).toMatchObject({ state: 'down', status: 'unreachable' })
    expect(linkOf(a, node('b', 'ns2', false), [{ partner: { in_touch: false } }]).state).toBe('down')
    expect(linkOf(a, null)).toBeNull()
  })

  it('follows the HA families that are configured', () => {
    expect(haFamilies([{ family: 'v6' }, { family: 'v4', enabled: false }])).toEqual(['v6'])
  })
})

describe('trace lanes', () => {
  const live = { dns: { enabled: true, series: [{ t: 1, v: 2 }] }, dhcp: { enabled: false, series: [] } }

  it('has a lane per source and always the events', () => {
    const lanes = traceLanes({ live, heartbeats: {}, events: [], families: ['v4', 'v6'], selfId: 'a', labels: LABELS, format: FORMAT })
    expect(lanes.map((l) => l.type)).toEqual(['line', 'ecg', 'events'])
    expect(lanes[1].rows.map((r) => r.label)).toEqual(['v4', 'v6'])
    expect(traceLanes({ live: null, families: [], labels: LABELS, format: FORMAT }).map((l) => l.key)).toEqual(['events'])
  })

  it('draws the heartbeats this node measured, else any server of the family', () => {
    const hb = { 'v4:b': { beats: [{ t: 5 }] }, 'v4:a': { beats: [{ t: 9 }] } }
    expect(heartbeatOf(hb, 'v4', 'a').beats[0].t).toBe(9)
    expect(heartbeatOf(hb, 'v4', 'z').beats[0].t).toBe(5)
    expect(heartbeatOf(hb, 'v6', 'a')).toBeNull()
  })

  it('reads the heartbeat interval and jitter, or the outage', () => {
    const beats = [30000, 20010, 9990, 0].map((t) => ({ t }))
    const ok = heartbeatReadout({ 'v4:a': { beats, state: 'hot-standby', inTouch: true } }, ['v4'], 'a')
    expect(ok.mean).toBeCloseTo(10000)
    expect(ok.sd).toBeGreaterThan(0)
    expect(ok.state).toBe('hot-standby')
    const lost = heartbeatReadout({ 'v4:a': { beats, inTouch: false, outage: { from: 123 } } }, ['v4'], 'a')
    expect(lost).toEqual({ lost: true, since: 123, state: undefined })
    expect(heartbeatReadout({}, [], 'a')).toBeNull()
  })

  it('moves "now" only for a server clock ahead of the browser', () => {
    expect(clockOffset(10500, 10000)).toBe(500)
    expect(clockOffset(9000, 10000)).toBe(0)
    expect(clockOffset(undefined, 10000)).toBe(0)
  })
})

describe('measured heartbeats', () => {
  const ha = (at, age, extra = {}) => ({ node_id: 'a', family: 'v4', state: 'hot-standby', collected_at: new Date(at).toISOString(), unsent_update_count: 0, partner: { in_touch: true, age }, ...extra })

  it('places beats from the partner age and opens an outage when the partner is lost', () => {
    let rec = observeHa(undefined, ha(10_400, 3))
    expect(rec.beats).toHaveLength(1)
    expect(rec.inTouch).toBe(true)
    rec = observeHa(rec, ha(21_000, 0))
    expect(rec.beats).toHaveLength(2)
    const lost = observeHa(rec, ha(25_000, 4, { state: 'partner-down', partner: { in_touch: false, age: 4 } }))
    expect(lost.inTouch).toBe(false)
    expect(lost.outage).toEqual({ from: 25_000, to: null })
    expect(lost.lost).toEqual([25_000])
    const again = observeHa(lost, ha(29_000, 8, { state: 'partner-down', partner: { in_touch: false } }))
    expect(again.outage.from).toBe(25_000)
    expect(again.lost).toEqual([29_000, 25_000])
    // Back in touch: the outage closes where it was seen ending, beats resume.
    const back = observeHa(again, ha(33_000, 0))
    expect(back.outage).toEqual({ from: 25_000, to: 33_000 })
    expect(back.beats).toHaveLength(3)
    // The first beat after the outage ends a span that is no heartbeat interval.
    expect(back.beats[0].afterGap).toBe(true)
    expect(back.gapPending).toBe(false)
    const narrowed = observeHa(back, ha(33_400, 0))
    expect(narrowed.beats[0].afterGap).toBe(true)
    const steady = observeHa(observeHa(narrowed, ha(43_000, 0)), ha(53_000, 0))
    // Four intervals between five beats, the one across the outage left out.
    expect(steady.beats).toHaveLength(5)
    expect(beatStats(steady.beats).count).toBe(3)
    expect(observeHa(back, { ...ha(34_000, 0), enabled: false })).toBe(back)
  })
})

describe('replication events', () => {
  beforeEach(() => resetClusterSignals())

  it('reports a node whose config version rises, not its first sighting', () => {
    expect(observeNodeVersion(node('a', 'ns1', true, { config_version: 42 }))).toBeNull()
    expect(observeNodeVersion(node('a', 'ns1', true, { config_version: 42 }))).toBeNull()
    const e = observeNodeVersion(node('a', 'ns1', true, { config_version: 43 }))
    expect(e).toMatchObject({ kind: 'repl', params: { version: 43, node: 'ns1' } })
  })
})

describe('zone transfers and HA transitions', () => {
  beforeEach(() => resetClusterSignals())
  const zone = (a, b, name = 'example.lan.') => ({ zone: name, view: '_default', serials: { A: a, B: b } })

  it('sees a transfer when a lagging node catches up, or when all nodes move on', () => {
    expect(observeZoneSerials([zone(5, 5)], 1000)).toEqual([])
    expect(observeZoneSerials([zone(6, 5)], 2000)).toEqual([])
    const [e] = observeZoneSerials([zone(6, 6)], 3000)
    expect(e).toMatchObject({ t: 3000, kind: 'axfr', key: 'events.axfr', params: { subject: 'example.lan', serial: 6 } })
    expect(observeZoneSerials([zone(6, 6)], 4000)).toEqual([])
    // The lag fell between two refreshes: both moved on together.
    expect(observeZoneSerials([zone(8, 8)], 5000)).toHaveLength(1)
    // A divergent zone and a missing summary are no transfer.
    expect(observeZoneSerials([zone(9, 8)], 6000)).toEqual([])
    expect(observeZoneSerials(undefined)).toEqual([])
    expect(observeZoneSerials([zone(9, 9)], 7000)).toHaveLength(1)
  })

  it('takes an ha/state message as a transition only when the state changes', () => {
    const msg = (state, inTouch = true) => ({ topic: 'ha', event: 'state', data: { server_name: 'ns1', family: 'v4', state, partner: { in_touch: inTouch } } })
    expect(isHaTransition(msg('partner-down', false))).toBe(true)
    expect(isHaTransition(msg('partner-down', false))).toBe(false)
    expect(isHaTransition({ ...msg('partner-down', false), data: { ...msg('partner-down', false).data, family: 'v6' } })).toBe(true)
    expect(isHaTransition(msg('hot-standby'))).toBe(true)
    expect(isHaTransition({ topic: 'alerts', event: 'opened', data: {} })).toBe(true)
  })
})

describe('pool alerts seen on the dashboard', () => {
  beforeEach(() => resetClusterSignals())
  const alert = (id, kind = 'pool_full') => ({ id, kind, subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', first_seen: '2026-01-01T00:00:00Z' })

  it('keeps an alert that leaves the open list as resolved, and ignores a list still loading', () => {
    expect(observePoolAlerts([alert('a'), { id: 'k', kind: 'insecure_key' }], 1000)).toBe(true)
    expect(observePoolAlerts([alert('a')], 1500)).toBe(false)
    expect(observePoolAlerts(null, 2000)).toBe(false)
    expect(poolAlertsSeen().resolved).toEqual([])
    expect(observePoolAlerts([], 3000)).toBe(true)
    expect(poolAlertsSeen().resolved).toEqual([expect.objectContaining({ id: 'a', t: 3000, resolved_at: new Date(3000).toISOString() })])
    // Past the window it is forgotten.
    expect(observePoolAlerts([], 3000 + 3600001)).toBe(true)
    expect(poolAlertsSeen().resolved).toEqual([])
  })
})
