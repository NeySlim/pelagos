// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  CUSTOM_PRESET, applyPreset, chartRows, extendUntil, fallbackBody, fallbackDefaults, fallbackErrors, fallbackStatus,
  hourChoices, nodeReadings, remaining, resolverSummary, rootRows, rootsAnswering, seriesQuery, toneOf, validAddress,
} from './resolverHealth'

const PRESETS = [
  { id: 'quad9', name: 'Quad9', forwarders: ['9.9.9.9', '2620:fe::fe'], tls_name: 'dns.quad9.net', filtering: true, builtin: true },
  { id: 'isp', name: 'ISP', forwarders: ['192.0.2.53'], tls_name: null, filtering: false, builtin: false },
]
const LAT = { warning: 800, critical: 1600 }

describe('resolver health helpers', () => {
  it('tones a value against warning and critical thresholds', () => {
    expect(toneOf(null, LAT)).toBe('neutral')
    expect(toneOf(200, LAT)).toBe('success')
    expect(toneOf(800, LAT)).toBe('warning')
    expect(toneOf(2000, LAT)).toBe('danger')
    expect(toneOf(5, undefined)).toBe('neutral')
  })

  it('reads the five measures of a node, null when never measured', () => {
    const r = nodeReadings({ rates: { queries_out: 3, servfail_clients_percent: null, cache_hit_percent: 80 }, latency_ms: { p95: 900 } }, { latency_p95_ms: LAT })
    expect(r.map((x) => x.key)).toEqual(['queriesOut', 'p95', 'servfail', 'valfail', 'cacheHit'])
    expect(r.find((x) => x.key === 'p95')).toMatchObject({ value: 900, tone: 'warning' })
    expect(r.find((x) => x.key === 'servfail').value).toBe(null)
    const high = nodeReadings({ rates: { servfail_clients_percent: 50, valfail_percent: 20 } }, { latency_p95_ms: LAT })
    expect(high.filter((x) => ['servfail', 'valfail'].includes(x.key)).map((x) => x.tone)).toEqual(['neutral', 'neutral'])
    expect(nodeReadings(null).every((x) => x.value === null)).toBe(true)
  })

  it('groups root probes by letter with the best time and the latest failure', () => {
    const entry = {
      roots: [
        { letter: 'b', address: '198.51.100.2', family: 4, rtt_ms: 30, ok: true, last_failure: '2026-10-28T10:00:00Z' },
        { letter: 'a', address: '198.51.100.1', family: 4, rtt_ms: 20, ok: true, last_failure: null },
        { letter: 'a', address: '2001:db8::1', family: 6, rtt_ms: 12, ok: true, last_failure: null },
        { letter: 'b', address: '2001:db8::2', family: 6, rtt_ms: null, ok: false, last_failure: '2026-10-29T10:00:00Z' },
        { letter: 'c', address: '198.51.100.3', family: 4, rtt_ms: null, ok: false, last_failure: null },
      ],
    }
    const rows = rootRows(entry)
    expect(rows.map((r) => r.letter)).toEqual(['a', 'b', 'c'])
    expect(rows[0]).toMatchObject({ rtt_ms: 12, ok: true, v4: { address: '198.51.100.1' }, v6: { address: '2001:db8::1' } })
    expect(rows[1]).toMatchObject({ rtt_ms: 30, ok: true, last_failure: '2026-10-29T10:00:00Z' })
    expect(rows[2]).toMatchObject({ ok: false, v6: null })
    expect(rootsAnswering(entry)).toEqual({ ok: 2, total: 3 })
  })

  it('merges series per node into chart rows and builds the query of a range', () => {
    const rows = chartRows([
      { key: { node_id: 'N1' }, points: [[100, 1], [200, 2]] },
      { key: { node_id: 'N2' }, points: [[200, 5], [300, 6]] },
    ])
    expect(rows).toEqual([{ ts: 100000, N1: 1 }, { ts: 200000, N1: 2, N2: 5 }, { ts: 300000, N2: 6 }])
    expect(seriesQuery('latency_p95_ms', '1h', null, 3600_000 * 10)).toEqual({ metric: 'latency_p95_ms', node_id: undefined, from: 32400, to: 36000, step: 60 })
    expect(seriesQuery('cache_hit_percent', '7d', 'N1', 0).step).toBe(3600)
  })

  it('offers durations up to fallback_max_hours', () => {
    expect(hourChoices(24)).toEqual([1, 2, 4, 8, 12, 24])
    expect(hourChoices(6)).toEqual([1, 2, 4, 6])
    expect(hourChoices(1)).toEqual([1])
    expect(hourChoices(undefined).at(-1)).toBe(24)
  })

  it('checks forwarder addresses: no port, no scope id', () => {
    for (const ok of ['9.9.9.9', '2620:fe::fe', '2001:db8::', '::1', '2001:db8:0:0:0:0:0:1', '::ffff:192.0.2.1']) expect(validAddress(ok), ok).toBe(true)
    for (const bad of ['', '9.9.9', '256.1.1.1', '9.9.9.9 port 53', 'fe80::1%eth0', '2001:db8::1::2', 'dns.quad9.net', '1:2:3:4:5:6:7:8:9']) expect(validAddress(bad), bad).toBe(false)
  })

  it('starts the form on the first preset, every node, at most 24 hours', () => {
    expect(fallbackDefaults(PRESETS, ['N1', 'N2'], 72)).toEqual({ preset: 'quad9', forwarders: ['9.9.9.9', '2620:fe::fe'], forward: 'first', node_ids: ['N1', 'N2'], hours: 24, tls: false, tls_name: '' })
    expect(fallbackDefaults(PRESETS, ['N1'], 6).hours).toBe(6)
    expect(fallbackDefaults([], [], 24).preset).toBe(CUSTOM_PRESET)
  })

  it('switches presets and drops DNS over TLS for a preset without a TLS host', () => {
    const form = { ...fallbackDefaults(PRESETS, ['N1'], 24), tls: true }
    expect(applyPreset(form, PRESETS, 'isp')).toMatchObject({ preset: 'isp', forwarders: ['192.0.2.53'], tls: false })
    expect(applyPreset(form, PRESETS, 'quad9').tls).toBe(true)
    expect(applyPreset(form, PRESETS, CUSTOM_PRESET).preset).toBe(CUSTOM_PRESET)
  })

  it('reports field errors as message keys', () => {
    const ok = fallbackDefaults(PRESETS, ['N1'], 24)
    expect(fallbackErrors(ok, 24)).toEqual({})
    expect(Object.keys(fallbackErrors({ ...ok, forwarders: [], node_ids: [], hours: 30 }, 24)).sort()).toEqual(['forwarders', 'hours', 'node_ids'])
    expect(fallbackErrors({ ...ok, forwarders: ['9.9.9.9 port 53'] }, 24).forwarders).toBe('resolverHealth.form.errors.address')
    expect(fallbackErrors({ ...ok, preset: CUSTOM_PRESET, tls: true, tls_name: '' }, 24).tls_name).toBeTruthy()
    expect(fallbackErrors({ ...ok, preset: CUSTOM_PRESET, tls: true, tls_name: 'dns.example.net' }, 24)).toEqual({})
  })

  it('builds the plan body: preset by id, node_ids only for a subset, TLS name only for own addresses', () => {
    const form = fallbackDefaults(PRESETS, ['N1', 'N2'], 24)
    expect(fallbackBody(form, ['N1', 'N2'])).toEqual({ forwarders: ['9.9.9.9', '2620:fe::fe'], forward: 'first', hours: 24, preset: 'quad9' })
    expect(fallbackBody({ ...form, tls: true, node_ids: ['N2'], forward: 'only', hours: 4 }, ['N1', 'N2'])).toEqual({
      forwarders: ['9.9.9.9', '2620:fe::fe'], forward: 'only', hours: 4, preset: 'quad9', tls: true, node_ids: ['N2'],
    })
    expect(fallbackBody({ ...form, preset: CUSTOM_PRESET, forwarders: [' 192.0.2.9 '], tls: true, tls_name: 'dns.example.net ' }, ['N1', 'N2'])).toEqual({
      forwarders: ['192.0.2.9'], forward: 'first', hours: 24, tls: true, tls_name: 'dns.example.net',
    })
  })

  it('tells the nodes still forwarding, the time left and a passed deadline', () => {
    const now = Date.parse('2026-10-29T10:00:00Z')
    const fb = { node_ids: ['N1', 'N2'], returned: ['N2'], until: '2026-10-29T12:30:00Z' }
    expect(fallbackStatus(fb, now)).toEqual({ pending: ['N1'], returned: ['N2'], remainingMs: 9000000, overdue: false })
    expect(fallbackStatus({ ...fb, until: '2026-10-29T09:00:00Z' }, now).overdue).toBe(true)
    expect(fallbackStatus(null)).toBe(null)
    expect(remaining(9000000)).toEqual({ hours: 2, minutes: 30 })
    expect(remaining(-1)).toBe(null)
    // One minute short of the asked hours, so the largest choice stays within fallback_max_hours.
    expect(extendUntil(2, now)).toBe('2026-10-29T11:59:00.000Z')
  })

  it('sums the cluster for the dashboard tile', () => {
    const node = (id, p95, servfail, since = null) => ({ node_id: id, error: null, latency_ms: { p95 }, rates: { servfail_clients_percent: servfail }, probes_healthy_since: since })
    const thresholds = { latency_p95_ms: LAT }
    expect(resolverSummary(null)).toBe(null)
    expect(resolverSummary({ nodes: [node('N1', 100, 1), node('N2', 300, 0.5)], thresholds, fallback: null })).toMatchObject({ p95: 300, servfail: 1, tone: 'success', nodes: 2, measured: 2 })
    expect(resolverSummary({ nodes: [node('N1', 900, 1)], thresholds }).tone).toBe('warning')
    expect(resolverSummary({ nodes: [node('N1', 100, 1, 'unhealthy')], thresholds })).toMatchObject({ tone: 'danger', unhealthy: 1 })
    expect(resolverSummary({ nodes: [node('N1', 100, 1)], thresholds, fallback: { forwarders: ['9.9.9.9'] } }).tone).toBe('warning')
    expect(resolverSummary({ nodes: [], thresholds }).tone).toBe('neutral')
  })
})
