// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  zoneMode, staticFindingId, editableZone, splitList, zoneForm, zoneEditChange, zoneEditDiff, zoneViews,
  zoneStats, catalogMemberBody, policyStatements, policyText, policyGrammarNames, policyErrors, dnssecOpBody,
  secondaryPeers, zoneDeleteRequest, newZoneAfter, CREATABLE_KINDS, nameServers, defaultNameServers,
  zoneCopies, secondaryChoice, hasRecords, zoneTabIds, forwardingNodes, forwardingDivergent, zoneErrorKey,
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

describe('newZoneAfter', () => {
  const ok = (n) => /^[a-z0-9.-]+$/.test(n)
  const form = (over) => ({ name: 'example.lan', kind: 'primary', view: '_default', file: '', primaries: '', forwarders: '', serverAddresses: '', serverNames: '', addzone: false, ...over })

  it('builds every kind the form offers', () => {
    expect(newZoneAfter(form(), ok).after).toEqual({ name: 'example.lan.', kind: 'primary', view: '_default', file: 'db.example.lan' })
    expect(newZoneAfter(form({ kind: 'mirror', primaries: '192.0.2.53' }), ok).after).toEqual({ name: 'example.lan.', kind: 'mirror', view: '_default', primaries: ['192.0.2.53'] })
    expect(newZoneAfter(form({ kind: 'static-stub', serverAddresses: '192.0.2.53\n2001:db8::53', serverNames: 'ns1.example.lan.' }), ok).after).toEqual({
      name: 'example.lan.', kind: 'static-stub', view: '_default',
      extra: { 'server-addresses': '{ 192.0.2.53; 2001:db8::53; }', 'server-names': '{ "ns1.example.lan"; }' },
    })
    expect(newZoneAfter(form({ kind: 'hint', name: 'ignored', file: 'root.hints' }), ok).after).toEqual({ name: '.', kind: 'hint', view: '_default', file: 'root.hints' })
    expect(newZoneAfter(form({ kind: 'redirect', primaries: '192.0.2.1' }), ok).after).toEqual({ name: '.', kind: 'redirect', view: '_default', primaries: ['192.0.2.1'] })
    expect(newZoneAfter(form({ kind: 'forward', forwarders: '192.0.2.1', addzone: true }), ok).after).toMatchObject({ forward: 'only', source: 'addzone' })
    expect(newZoneAfter(form({ kind: 'mirror', name: '.', addzone: true }), ok).after).toEqual({ name: '.', kind: 'mirror', view: '_default' })
  })

  it('reports what BIND would refuse', () => {
    expect(newZoneAfter(form({ name: 'bad name' }), ok).errors).toEqual({ name: 'name' })
    expect(newZoneAfter(form({ kind: 'mirror' }), ok).errors).toEqual({ primaries: 'list' })
    expect(newZoneAfter(form({ kind: 'static-stub' }), ok).errors).toEqual({ serverAddresses: 'list' })
    expect(newZoneAfter(form({ kind: 'hint' }), ok).errors).toEqual({ file: 'required' })
    expect(newZoneAfter(form({ kind: 'redirect' }), ok).errors).toEqual({ file: 'fileOrPrimaries' })
    expect(newZoneAfter(form({ kind: 'secondary' }), ok).errors).toEqual({ primaries: 'list' })
    expect(CREATABLE_KINDS).toEqual(expect.arrayContaining(['mirror', 'static-stub', 'hint', 'redirect']))
  })
})

describe('name servers of a new primary', () => {
  const ok = (n) => /^[a-z0-9.-]+$/.test(n)
  const node = (name, url, withBind = true) => ({ peer: { name, web_url: url, modules: { bind: withBind } } })

  it('are proposed from the nodes running BIND', () => {
    expect(defaultNameServers([node('ns1', 'https://ns1.example.lan:8443'), node('ns2', 'https://192.0.2.12:8443'), node('dhcp', 'https://dhcp.example.lan:8443', false)]))
      .toBe('ns1.example.lan.\nns2 192.0.2.12')
    expect(defaultNameServers([node('ns1', 'https://[2001:db8::11]:8443', false)])).toBe('ns1 2001:db8::11')
    expect(defaultNameServers([])).toBe('')
  })

  it('are computed against the zone being created', () => {
    const named = [
      { peer: { name: 'ns1', web_url: 'https://ns1.example.lan:8443', url: 'https://192.0.2.11:8444', modules: { bind: true } } },
      node('ns2', 'https://ns2.example.lan:8443'),
    ]
    const proposed = defaultNameServers(named, 'example.lan')
    expect(proposed).toBe('ns1.example.lan. 192.0.2.11\nns2.example.lan.')
    // A node without a known address keeps its line and gets the glue hint before submit.
    expect(nameServers(proposed, 'example.lan.', ok).error).toBe('nsGlue')
    expect(nameServers(defaultNameServers(named.slice(0, 1), 'example.lan.'), 'example.lan.', ok)).toEqual({
      ns: ['ns1.example.lan.'],
      records: [{ name: 'ns1.example.lan.', rtype: 'A', ttl: 3600, rdata: ['192.0.2.11'] }],
    })
    expect(defaultNameServers(named, 'other.example.org')).toBe('ns1.example.lan.\nns2.example.lan.')
  })

  it('never hang an address-only node off a reverse zone', () => {
    const lab = [node('ns1', 'https://192.0.2.11:8443'), node('ns2', 'https://192.0.2.12:8443')]
    expect(defaultNameServers(lab, '2.0.192.in-addr.arpa')).toBe('')
    expect(defaultNameServers(lab, '8.b.d.0.1.0.0.2.ip6.arpa.')).toBe('')
    expect(defaultNameServers([node('ns1', 'https://ns1.example.lan:8443')], '2.0.192.in-addr.arpa.')).toBe('ns1.example.lan.')
    expect(defaultNameServers(lab, 'example.lan')).toBe('ns1 192.0.2.11\nns2 192.0.2.12')
  })

  it('hang short names off the zone and add their address records', () => {
    expect(nameServers('ns1 192.0.2.53\nns2.example.net.\nns3 2001:db8::53', 'z.example.lan.', ok)).toEqual({
      ns: ['ns1.z.example.lan.', 'ns2.example.net.', 'ns3.z.example.lan.'],
      records: [
        { name: 'ns1.z.example.lan.', rtype: 'A', ttl: 3600, rdata: ['192.0.2.53'] },
        { name: 'ns3.z.example.lan.', rtype: 'AAAA', ttl: 3600, rdata: ['2001:db8::53'] },
      ],
    })
    expect(nameServers('', 'z.example.lan.', ok)).toEqual({ ns: [], records: [] })
  })

  it('refuse localhost, bad addresses and in-zone names without an address', () => {
    expect(nameServers('localhost.', 'z.example.lan.', ok).error).toBe('nsLocalhost')
    expect(nameServers('ns1 not-an-ip', 'z.example.lan.', ok).error).toBe('nsAddress')
    expect(nameServers('ns1.z.example.lan.', 'z.example.lan.', ok).error).toBe('nsGlue')
    expect(nameServers('ns1 192.0.2.1 extra', 'z.example.lan.', ok).error).toBe('nsName')
    const form = { name: 'z.example.lan', kind: 'primary', view: '_default', ns: 'localhost.' }
    expect(newZoneAfter(form, ok).errors).toEqual({ ns: 'nsLocalhost' })
    expect(newZoneAfter({ ...form, ns: 'ns1.example.net.' }, ok).after.ns).toEqual(['ns1.example.net.'])
  })
})

describe('secondaries of a primary', () => {
  const node = (id, bind = true) => ({ peer: { id, name: id, modules: { bind } } })
  const nodes = [node('ns1'), node('ns2'), node('ns3'), node('ns4'), node('dhcp1', false)]

  it('reads the copies, else the status entries that hold the zone', () => {
    const copies = { ns1: { kind: 'primary', source: 'pelagos' }, ns2: { kind: 'secondary', source: 'pelagos' } }
    expect(zoneCopies({ copies })).toBe(copies)
    const status = { ns1: { kind: 'primary' }, ns2: { kind: 'secondary' }, ns3: { kind: null, error: 'zone not configured' } }
    expect(Object.keys(zoneCopies({ status }))).toEqual(['ns1', 'ns2'])
  })

  it('offers every BIND node but the primary, the current secondaries ticked', () => {
    const detail = { copies: { ns2: { kind: 'primary' }, ns1: { kind: 'secondary' }, ns3: { kind: 'secondary' } } }
    expect(secondaryChoice(detail, nodes)).toEqual({ primary: 'ns2', current: ['ns1', 'ns3'], candidates: ['ns1', 'ns3', 'ns4'] })
    expect(secondaryChoice({ copies: { ns1: { kind: 'secondary' } } }, nodes)).toBeNull()
  })
})

describe('zones without records', () => {
  it('never offers records for forward, hint, stub and static-stub zones', () => {
    for (const kind of ['forward', 'hint', 'stub', 'static-stub']) expect(hasRecords(kind)).toBe(false)
    expect(hasRecords('primary')).toBe(true)
    expect(zoneTabIds('forward')).toEqual(['forwarding', 'config'])
    expect(zoneTabIds('stub')).toEqual(['status', 'config'])
    expect(zoneTabIds('secondary')).toEqual(['records', 'status', 'config'])
  })

  it('lists the nodes holding the forward zone first and spots a divergence', () => {
    const same = {
      ns2: { present: true, forward: 'only', forwarders: ['192.0.2.2', '192.0.2.1'], reach: [] },
      ns1: { present: true, forward: 'only', forwarders: ['192.0.2.1', '192.0.2.2'], reach: [] },
      ns3: { present: false, forward: null, forwarders: [], reach: null },
    }
    expect(forwardingNodes(same).map((n) => n.id)).toEqual(['ns1', 'ns2', 'ns3'])
    expect(forwardingDivergent(same)).toBe(false)
    expect(forwardingDivergent({ ...same, ns2: { ...same.ns2, forward: 'first' } })).toBe(true)
    expect(forwardingDivergent({ ...same, ns2: { ...same.ns2, error: 'unreachable', forwarders: [] } })).toBe(false)
  })

  it('maps zone page errors to translated texts by code', () => {
    expect(zoneErrorKey({ code: 'zone_without_records', status: 409 })).toBe('detail.errors.noRecords')
    expect(zoneErrorKey({ code: 'not_found', status: 404 })).toBe('detail.errors.notFound')
    expect(zoneErrorKey({ code: 'engine_unavailable', status: 503 })).toBe('detail.errors.unavailable')
    expect(zoneErrorKey({ code: 'network_error', status: 0 })).toBe('detail.errors.network')
    expect(zoneErrorKey({ code: 'internal_error', status: 500 })).toBe('detail.errors.generic')
  })
})
