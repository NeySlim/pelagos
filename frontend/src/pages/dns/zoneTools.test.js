// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  zoneMode, staticFindingId, editableZone, splitList, zoneForm, zoneEditChange, zoneEditDiff, zoneViews,
  zoneStats, catalogMemberBody, policyStatements, policyText, policyGrammarNames, policyErrors, dnssecOpBody,
  secondaryPeers, zoneDeleteRequest,
} from './zoneTools'

const zone = {
  name: 'lab.example.lan.', kind: 'primary', view: '_default', dynamic: true, source: 'pelagos',
  primaries: [], also_notify: ['192.0.2.2'], allow_transfer: ['key ddi-read'], allow_update: [],
  update_policy: ['grant ddi-admin zonesub A'], forwarders: [], forward: null, dnssec_policy: null,
  inline_signing: null, notes: null, extra: { notify: 'explicit' },
}

describe('zone modes', () => {
  it('reads the mode from the API or derives it', () => {
    expect(zoneMode({ mode: 'static', zone })).toBe('static')
    expect(zoneMode({ zone })).toBe('dynamic')
    expect(zoneMode({ ...zone, dynamic: false })).toBe('static')
    expect(zoneMode({ zone: { kind: 'secondary' } })).toBe('secondary')
    expect(zoneMode(null)).toBe(null)
  })
  it('names the conversion finding and editable sources', () => {
    expect(staticFindingId({ name: 'static.lan.' })).toBe('bind:static_zone:_default/static.lan.')
    expect(staticFindingId({ name: 's.lan.', view: 'inside' })).toBe('bind:static_zone:inside/s.lan.')
    expect(editableZone(zone)).toBe(true)
    expect(editableZone({ source: 'addzone' })).toBe(true)
    expect(editableZone({ source: 'user_conf' })).toBe(false)
  })
})

describe('zone edit', () => {
  it('builds a replace change that keeps the rest of the zone', () => {
    const form = zoneForm(zone)
    expect(form.also_notify).toBe('192.0.2.2')
    expect(zoneEditDiff(zone, form)).toEqual([])
    form.also_notify = '192.0.2.2\n192.0.2.3;192.0.2.4'
    form.dnssec_policy = 'default'
    form.inline_signing = true
    const change = zoneEditChange(zone, form)
    expect(change.op).toBe('replace')
    expect(change.target).toBe('_default/lab.example.lan.')
    expect(change.after.also_notify).toEqual(['192.0.2.2', '192.0.2.3', '192.0.2.4'])
    expect(change.after.extra).toEqual({ notify: 'explicit' })
    expect(change.after.dnssec_policy).toBe('default')
    expect(zoneEditDiff(zone, form)).toEqual(['also_notify', 'dnssec_policy', 'inline_signing'])
    expect(splitList(' a ;\n\nb')).toEqual(['a', 'b'])
  })
  it('lists views and computes stats from the whole list', () => {
    const items = [
      { zone: { name: 'a.', view: 'outside', kind: 'primary', dynamic: false } },
      { zone: { name: 'a.', view: 'inside', kind: 'primary', dynamic: true }, divergent: true },
      { zone: { name: 'b.', view: 'inside', kind: 'secondary' } },
    ]
    expect(zoneViews(items, 'a.')).toEqual(['inside', 'outside'])
    expect(zoneStats(items, ['secondary'])).toEqual({ total: 3, primary: 2, secondary: 1, static: 1, divergent: 1 })
  })
})

describe('catalog and dnssec bodies', () => {
  it('builds catalog member bodies', () => {
    expect(catalogMemberBody({ op: 'add', member: ' new.lan ', group: 'lab', view: '_default' })).toEqual({ op: 'add', member: 'new.lan', group: 'lab' })
    expect(catalogMemberBody({ op: 'delete', member: 'x.lan', group: 'lab', view: 'inside' })).toEqual({ op: 'delete', member: 'x.lan', view: 'inside' })
  })
  it('parses and checks policy statements against the grammar', () => {
    const statements = policyStatements('keys { csk lifetime unlimited algorithm ecdsap256sha256; };\nsignatures-validity 14d\n\n')
    expect(statements).toEqual([
      { name: 'keys', value: '{ csk lifetime unlimited algorithm ecdsap256sha256; }' },
      { name: 'signatures-validity', value: '14d' },
    ])
    expect(policyText(statements)).toBe('keys { csk lifetime unlimited algorithm ecdsap256sha256; };\nsignatures-validity 14d;')
    const names = policyGrammarNames({ contexts: { 'dnssec-policy': { statements: { keys: {}, 'max-zone-ttl': {} } } } })
    expect(names).toEqual(['keys', 'max-zone-ttl'])
    expect(policyGrammarNames({ statements: [{ name: 'keys', contexts: ['dnssec-policy'] }, { name: 'x', contexts: ['options'] }] })).toEqual(['keys'])
    expect(policyErrors([{ name: 'bogus', value: '1' }, { name: 'keys', value: '' }], names)).toEqual([
      { name: 'bogus', error: 'unknown' },
      { name: 'keys', error: 'empty' },
    ])
  })
  it('builds dnssec operation bodies', () => {
    expect(dnssecOpBody({ action: 'rollover', key_id: '4242' })).toEqual({ action: 'rollover', key_id: 4242 })
    expect(dnssecOpBody({ action: 'checkds', key_id: '', view: 'inside', node_id: 'n2' })).toEqual({ action: 'checkds', state: 'published', view: 'inside', node_id: 'n2' })
  })
})

describe('zone deletion across peers', () => {
  const status = { self: { kind: 'primary' }, ns2: { kind: 'secondary' }, ns3: { kind: 'primary' } }

  it('finds the peers holding the managed primary as a secondary', () => {
    expect(secondaryPeers({ zone, status }, 'self')).toEqual(['ns2'])
    expect(secondaryPeers({ zone: { ...zone, source: 'user_conf' }, status }, 'self')).toEqual([])
    expect(secondaryPeers({ zone: { ...zone, kind: 'secondary' }, status }, 'self')).toEqual([])
    expect(secondaryPeers(null, 'self')).toEqual([])
  })

  it('sends those peers as node_ids, and none when the copy is local only', () => {
    const withPeers = zoneDeleteRequest(zone, ['ns2'])
    expect(withPeers.node_ids).toEqual(['ns2'])
    expect(withPeers.change).toEqual({ op: 'delete', target: '_default/lab.example.lan.', before: zone, after: null })
    expect(zoneDeleteRequest(zone, []).node_ids).toBeUndefined()
  })
})
