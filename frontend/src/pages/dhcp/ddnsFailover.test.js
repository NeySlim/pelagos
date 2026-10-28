// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  alertsByZone, blockerAction, failoverPath, isPreparable, isPrepared, outageSummary, replayBody, targetNodes,
  resilienceSummary, toLocalInput, zoneKey, zoneResilience, zoneState,
} from './ddnsFailover'

const zone = (extra = {}) => ({ zone: 'example.lan.', view: '_default', primary_node_id: 'N1', epoch: 1, copies: ['N2'], ready: true, blockers: [], stale: [], ...extra })
const msg = (key, params = {}) => ({ key, params })

describe('ddns failover helpers', () => {
  it('builds keys and the failover path', () => {
    expect(zoneKey(zone())).toBe('_default/example.lan.')
    expect(failoverPath()).toBe('/dhcp/v4/ddns?tab=failover')
    expect(failoverPath('internal/corp.example.lan.')).toBe('/dhcp/v4/ddns?tab=failover&zone=internal%2Fcorp.example.lan.')
  })

  it('ranks the zone state: outage, stale, blocked, not prepared, ready', () => {
    const alerts = alertsByZone([
      { kind: 'ddns_outage', state: 'open', subject: 'ddns:_default/example.lan.' },
      { kind: 'dns_stale_primary', state: 'open', subject: 'ddns:stale:_default/b.example.' },
      { kind: 'ddns_outage', state: 'resolved', subject: 'ddns:_default/c.example.' },
    ])
    expect(zoneState(zone(), alerts)).toBe('outage')
    expect(zoneState(zone({ zone: 'b.example.' }), alerts)).toBe('stale')
    expect(zoneState(zone({ zone: 'c.example.', stale: ['N1'] }), alerts)).toBe('stale')
    expect(zoneState(zone({ zone: 'c.example.' }), alerts)).toBe('ready')
    expect(zoneState(zone({ ready: false, epoch: 0, blockers: [msg('ddns.blocker.not_prepared')] }))).toBe('not_prepared')
    expect(zoneState(zone({ ready: false, blockers: [msg('ddns.blocker.signed', { zone: 'example.lan.' })] }))).toBe('blocked')
  })

  it('tells prepared and preparable zones apart', () => {
    expect(isPrepared(zone())).toBe(true)
    expect(isPrepared(zone({ epoch: 0 }))).toBe(false)
    expect(isPreparable(zone({ ready: false, epoch: 0, blockers: [msg('ddns.blocker.not_prepared')] }))).toBe(true)
    expect(isPreparable(zone({ ready: false, blockers: [msg('ddns.blocker.no_copy')] }))).toBe(false)
  })

  it('links an unmanaged zone to its handover and a transfer refusal to the zone', () => {
    const z = zone({ zone: 'corp.example.lan.', view: 'internal' })
    expect(blockerAction(msg('ddns.blocker.not_managed', { zone: 'corp.example.lan.', node: 'ns1' }), z)).toEqual({ to: '/dns/zones/corp.example.lan?view=internal', label: 'adopt' })
    expect(blockerAction(msg('ddns.blocker.no_transfer', { zone: 'example.lan.' }), zone()).label).toBe('openZone')
    expect(blockerAction(msg('ddns.blocker.signed', { zone: 'example.lan.' }), zone())).toBeNull()
  })

  it('offers as targets the online nodes holding a copy of every zone', () => {
    expect(targetNodes([zone({ copies: ['N2', 'N3'] }), zone({ copies: ['N3', 'N2'] })], ['N3'])).toEqual(['N2'])
    expect(targetNodes([zone({ copies: ['N2'] }), zone({ copies: ['N3'] })])).toEqual([])
  })

  it('summarises the outage and what can be promoted', () => {
    const a = { kind: 'ddns_outage', state: 'open', subject: 'ddns:_default/example.lan.', details: { since: '2026-10-28T10:00:00Z' } }
    const b = { ...a, subject: 'ddns:_default/b.example.', details: { since: '2026-10-28T09:00:00Z' } }
    const { outage } = alertsByZone([a, b])
    const out = outageSummary([zone(), zone({ zone: 'b.example.', epoch: 0, ready: false })], outage)
    expect(out.since).toBe('2026-10-28T09:00:00Z')
    expect(out.items).toHaveLength(2)
    expect(out.promotable.map((z) => z.zone)).toEqual(['example.lan.'])
  })

  it('builds the replay body from the form', () => {
    const from = toLocalInput('2026-10-28T08:00:00Z')
    const to = toLocalInput('2026-10-28T09:30:00Z')
    expect(replayBody({ from, to, family: 'v4', limit: '50' }).body).toEqual({ from: '2026-10-28T08:00:00.000Z', to: '2026-10-28T09:30:00.000Z', family: 'v4', limit: 50 })
    expect(replayBody({ from: '', to: '', family: '', limit: '' }).body).toEqual({})
    expect(replayBody({ from: to, to: from }).error).toBe('ddnsFailover.replay.order')
    expect(replayBody({ from: toLocalInput('2026-10-20T00:00:00Z'), to }).error).toBe('ddnsFailover.replay.tooLong')
    expect(replayBody({ limit: '0' }).error).toBe('ddnsFailover.replay.badLimit')
  })
  it('sums up the resilience for the dashboard and finds a zone for its badge', () => {
    const res = { zones: [zone(), zone({ zone: 'b.example.', ready: false })], outage: null, replay: { candidates: 2 } }
    expect(resilienceSummary(res)).toMatchObject({ total: 2, ready: 1, stale: 0, replay: 2, tone: 'warning' })
    expect(resilienceSummary({ ...res, outage: { since: 'x', zones: [] } }).tone).toBe('danger')
    expect(resilienceSummary({ zones: [zone()] }).tone).toBe('success')
    expect(zoneResilience(res, 'example.lan', '_default')?.zone).toBe('example.lan.')
    expect(zoneResilience(res, 'example.lan.', 'internal')).toBeNull()
  })
})
