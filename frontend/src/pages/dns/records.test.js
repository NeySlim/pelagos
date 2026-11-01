// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import {
  absoluteName, relativeName, validOwner, validDomainName, isIPv4, isIPv6, validateRdata, normalizeRdata,
  validateForm, buildChanges, localDiff, validForwarder, composeRdata, fieldDefaults, RDATA_FIELDS, EDITABLE_TYPES,
} from './records'
import { laggingNodes, resolverChanges, resynchronizeZone, zoneHref } from './helpers'

describe('owner names', () => {
  it('converts between relative and absolute forms', () => {
    expect(absoluteName('www', 'example.lan')).toBe('www.example.lan.')
    expect(absoluteName('@', 'example.lan.')).toBe('example.lan.')
    expect(absoluteName('', 'example.lan.')).toBe('example.lan.')
    expect(absoluteName('Host.Example.Lan.', 'example.lan.')).toBe('host.example.lan.')
    expect(relativeName('www.example.lan.', 'example.lan.')).toBe('www')
    expect(relativeName('example.lan.', 'example.lan.')).toBe('@')
    expect(relativeName('a.b.example.lan.', 'example.lan')).toBe('a.b')
  })

  it('rejects names outside the zone and bad labels', () => {
    expect(validOwner('www', 'example.lan.')).toBe(true)
    expect(validOwner('*.dyn', 'example.lan.')).toBe(true)
    expect(validOwner('_sip._tcp', 'example.lan.')).toBe(true)
    expect(validOwner('www.other.lan.', 'example.lan.')).toBe(false)
    expect(validOwner('a.*.b', 'example.lan.')).toBe(false)
    expect(validOwner('-bad', 'example.lan.')).toBe(false)
    expect(validOwner('a..b', 'example.lan.')).toBe(false)
    expect(validOwner('_dmarc', 'example.lan.', 'TXT')).toBe(true)
    expect(validOwner('host_1', 'example.lan.', 'A')).toBe(false)
    expect(validOwner('*.dyn', 'example.lan.', 'AAAA')).toBe(true)
    expect(validateForm({ owner: 'host_1', rtype: 'A', ttl: 300, rdata: '192.0.2.1' }, 'example.lan.').errors.owner).toBe('hostOwner')
    expect(validateForm({ owner: 'x', rtype: 'A', ttl: -5, rdata: '192.0.2.1' }, 'example.lan.').errors.ttl).toBe('ttl')
  })

  it('validates zone names', () => {
    expect(validDomainName('example.lan')).toBe(true)
    expect(validDomainName('2.0.192.in-addr.arpa.')).toBe(true)
    expect(validDomainName('')).toBe(false)
    expect(validDomainName('*.example.lan')).toBe(false)
  })
})

describe('addresses', () => {
  it('parses IPv4 and IPv6', () => {
    expect(isIPv4('192.0.2.1')).toBe(true)
    expect(isIPv4('192.0.2.256')).toBe(false)
    expect(isIPv4('192.0.2.01')).toBe(false)
    expect(isIPv6('2001:db8::1')).toBe(true)
    expect(isIPv6('::1')).toBe(true)
    expect(isIPv6('::ffff:192.0.2.1')).toBe(true)
    expect(isIPv6('2001:db8::1::2')).toBe(false)
    expect(isIPv6('2001:db8:0:0:0:0:0:1:2')).toBe(false)
    expect(isIPv6('192.0.2.1')).toBe(false)
  })

  it('validates forwarders with an optional port', () => {
    expect(validForwarder('192.0.2.1')).toBe(true)
    expect(validForwarder('2001:db8::53 port 5353')).toBe(true)
    expect(validForwarder('192.0.2.1 port')).toBe(false)
    expect(validForwarder('resolver.example.lan')).toBe(false)
  })
})

describe('rdata validation', () => {
  it.each([
    ['A', '192.0.2.10', null],
    ['A', '2001:db8::1', 'ipv4'],
    ['AAAA', '2001:db8::10', null],
    ['AAAA', '192.0.2.1', 'ipv6'],
    ['CNAME', 'host.example.lan.', null],
    ['CNAME', 'two words', 'hostname'],
    ['MX', '10 mail.example.lan.', null],
    ['MX', 'mail.example.lan.', 'mx'],
    ['SRV', '0 5 5060 sip.example.lan.', null],
    ['SRV', '0 5 sip.example.lan.', 'srv'],
    ['TXT', '"v=spf1 -all"', null],
    ['TXT', '"a" "b"', null],
    ['TXT', `"${'x'.repeat(256)}"`, 'txt'],
    ['CAA', '0 issue "ca.example.lan"', null],
    ['CAA', '0 issue ca.example.lan', 'caa'],
    ['PTR', '', 'rdataEmpty'],
  ])('%s %s', (type, value, expected) => {
    expect(validateRdata(type, value)).toBe(expected)
  })

  it('quotes bare TXT values with spaces and lowercases targets', () => {
    expect(normalizeRdata('TXT', 'hello world')).toBe('"hello world"')
    expect(normalizeRdata('CNAME', 'Host.Example.Lan.')).toBe('host.example.lan.')
  })
})

describe('validateForm', () => {
  it('builds the after RRset and deduplicates values', () => {
    const { errors, rrset } = validateForm({ owner: 'www', rtype: 'A', ttl: '300', rdata: '192.0.2.1\n192.0.2.1\n\n192.0.2.2' }, 'example.lan.')
    expect(errors).toEqual({})
    expect(rrset).toEqual({ name: 'www.example.lan.', rtype: 'A', ttl: 300, rdata: ['192.0.2.1', '192.0.2.2'] })
  })

  it('reports each invalid field', () => {
    const { errors } = validateForm({ owner: 'a..b', rtype: 'SOA', ttl: '-1', rdata: '' }, 'example.lan.')
    expect(errors).toEqual({ owner: 'owner', rtype: 'type', ttl: 'ttl', rdata: 'rdataEmpty' })
  })

  it('refuses a CNAME with two values', () => {
    expect(validateForm({ owner: 'x', rtype: 'CNAME', ttl: '60', rdata: 'a.example.lan.\nb.example.lan.' }, 'example.lan.').errors.rdata).toBe('singleton')
  })
})

describe('buildChanges', () => {
  const before = { name: 'www.example.lan.', rtype: 'A', ttl: 300, rdata: ['192.0.2.1'] }
  const after = { name: 'www.example.lan.', rtype: 'A', ttl: 600, rdata: ['192.0.2.1', '192.0.2.2'] }

  it('uses the section 6 target grammar', () => {
    expect(buildChanges({ zone: 'example.lan', mode: 'add', before: null, after })).toEqual([
      { op: 'add', target: 'example.lan./www/A', before: null, after, node_ids: [] },
    ])
    expect(buildChanges({ zone: 'example.lan.', mode: 'edit', before, after })[0]).toMatchObject({ op: 'replace', target: 'example.lan./www/A', before })
    expect(buildChanges({ zone: 'example.lan.', mode: 'delete', before })[0]).toEqual({ op: 'delete', target: 'example.lan./www/A', before, after: null, node_ids: [] })
  })

  it('turns an add onto an existing RRset into a replace', () => {
    expect(buildChanges({ zone: 'example.lan.', mode: 'add', before, after })[0].op).toBe('replace')
  })

  it('splits a rename into delete and add', () => {
    const renamed = { ...after, name: 'web.example.lan.' }
    const changes = buildChanges({ zone: 'example.lan.', mode: 'edit', before, after: renamed })
    expect(changes.map((c) => [c.op, c.target])).toEqual([
      ['delete', 'example.lan./www/A'],
      ['add', 'example.lan./web/A'],
    ])
    expect(changes[1].after).toEqual(renamed)
  })

  it('marks the apex with @', () => {
    const apex = { name: 'example.lan.', rtype: 'MX', ttl: 3600, rdata: ['10 mail.example.lan.'] }
    expect(buildChanges({ zone: 'example.lan.', mode: 'add', before: null, after: apex })[0].target).toBe('example.lan./@/MX')
  })
})

describe('localDiff', () => {
  it('shows removed and added lines only', () => {
    const diff = localDiff({ name: 'a.', rtype: 'A', ttl: 60, rdata: ['192.0.2.1', '192.0.2.2'] }, { name: 'a.', rtype: 'A', ttl: 60, rdata: ['192.0.2.2', '192.0.2.3'] }, 'z')
    expect(diff).toContain('-a. 60 IN A 192.0.2.1')
    expect(diff).toContain(' a. 60 IN A 192.0.2.2')
    expect(diff).toContain('+a. 60 IN A 192.0.2.3')
    expect(localDiff(null, null)).toBe('')
  })
})

describe('DNS helpers', () => {
  it('finds nodes behind the highest serial', () => {
    expect(laggingNodes({ n1: 5, n2: 4, n3: null })).toEqual(['n2', 'n3'])
    expect(laggingNodes({ n1: 5, n2: 5 })).toEqual([])
    expect(laggingNodes({})).toEqual([])
  })

  it('links zones without the trailing dot and keeps the view', () => {
    expect(zoneHref('example.lan.')).toBe('/dns/zones/example.lan')
    expect(zoneHref('example.lan.', 'internal')).toBe('/dns/zones/example.lan?view=internal')
  })

  it('keeps only the resolver keys that changed', () => {
    const cur = { recursion: true, allow_recursion: ['internal'], forwarders: [], forward: null, dnssec_validation: 'auto' }
    expect(resolverChanges(cur, { ...cur, forwarders: ['192.0.2.1'] })).toEqual({ forwarders: ['192.0.2.1'] })
    expect(resolverChanges(cur, { ...cur })).toEqual({})
    expect(resolverChanges(cur, { ...cur, allow_recursion: ['any'], dnssec_validation: 'no' })).toEqual({ 'allow-recursion': ['any'], 'dnssec-validation': 'no' })
  })

  it('retransfers lagging secondaries and notifies from primaries', async () => {
    const calls = []
    const dnsApi = {
      retransfer: async (zone, node, view) => calls.push(['retransfer', zone, node, view]) && { output: 'ok' },
      notify: async (zone, body) => calls.push(['notify', zone, body]) && { output: 'queued' },
    }
    await resynchronizeZone({ zone: 'partner.example.', kind: 'secondary', serials: { n1: 3, n2: 2 } }, dnsApi)
    await resynchronizeZone({ zone: 'example.lan.', kind: 'primary', view: 'internal', serials: { n1: 3 } }, dnsApi)
    expect(calls).toEqual([
      ['retransfer', 'partner.example', 'n2', undefined],
      ['notify', 'example.lan', { view: 'internal' }],
    ])
  })
})

describe('record types of 0.4.0', () => {
  const fp = 'd2abde240d7cd3ee6b4b28c54df034b97983a1d16e8a410e4561cb106618e971'
  it('accepts the documented forms', () => {
    for (const [rtype, value] of [
      ['SSHFP', `4 2 ${fp}`],
      ['SSHFP', '1 1 123456789abcdef67890123456789abcdef67890'],
      ['TLSA', `3 1 1 ${fp.toUpperCase()}`],
      ['TLSA', `3 1 2 ${'ab'.repeat(64)}`],
      ['HTTPS', '1 . alpn="h3,h2" port=8443'],
      ['HTTPS', '0 cdn.example.net.'],
      ['SVCB', '1 dot.example.lan. alpn=dot port=853'],
      ['NAPTR', '100 10 "S" "SIP+D2U" "" _sip._udp.example.lan.'],
      ['NAPTR', '100 10 "u" "E2U+sip" "!^.*$!sip:info@example.lan!" .'],
      ['LOC', '52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000.00m 10.00m'],
      ['LOC', '52 N 4 E 3m'],
      ['DNAME', 'example.net.'],
      ['DS', `60485 13 2 ${fp}`],
      ['URI', '10 1 "https://www.example.lan/"'],
    ]) expect(validateRdata(rtype, value), `${rtype} ${value}`).toBeNull()
  })

  it('refuses wrong shapes with the type key', () => {
    for (const [rtype, value] of [
      ['SSHFP', '4 2 abcd'],
      ['SSHFP', '4 x ' + fp],
      ['TLSA', '3 1 1 xyz'],
      ['TLSA', '3 1 2 ' + fp],
      ['HTTPS', '0 . alpn=h2'],
      ['SVCB', 'x svc.example.lan.'],
      ['NAPTR', '100 10 S SIP "" .'],
      ['LOC', 'north pole'],
      ['DS', '70000 13 2 ' + fp],
      ['DS', '60485 13 1 ' + fp],
      ['URI', '10 1 https://x'],
    ]) expect(validateRdata(rtype, value), `${rtype} ${value}`).toBe(`records.types.errors.${rtype}`)
    expect(validateRdata('DNAME', 'two words')).toBe('hostname')
  })

  it('composes values from the assisted fields', () => {
    expect(composeRdata('SSHFP', { ...fieldDefaults('SSHFP'), fingerprint: 'AA:BB' })).toBe('4 2 aabb')
    expect(composeRdata('TLSA', fieldDefaults('TLSA'))).toBe('')
    expect(composeRdata('TLSA', { ...fieldDefaults('TLSA'), data: fp })).toBe(`3 1 1 ${fp}`)
    expect(composeRdata('HTTPS', { priority: '1', target: '.', params: 'alpn="h2"' })).toBe('1 . alpn="h2"')
    expect(composeRdata('NAPTR', { order: '100', preference: '10', flags: 'S', services: 'SIP+D2U', regexp: '', replacement: '_sip._udp' }))
      .toBe('100 10 "S" "SIP+D2U" "" _sip._udp')
    expect(composeRdata('LOC', { latitude: '52.373', longitude: '-4.9', altitude: '2' })).toBe('52 22 22.800 N 4 54 0.000 W 2m')
    expect(composeRdata('LOC', { latitude: '91', longitude: '0' })).toBe('')
    expect(composeRdata('DS', { keyTag: '60485', algorithm: '13', digestType: '2', digest: fp.toUpperCase() })).toBe(`60485 13 2 ${fp}`)
    expect(composeRdata('URI', { priority: '10', weight: '1', target: 'https://a/' })).toBe('10 1 "https://a/"')
    for (const rtype of Object.keys(RDATA_FIELDS)) expect(EDITABLE_TYPES).toContain(rtype)
  })

  it('normalizes digests and DNAME targets as the server prints them', () => {
    expect(normalizeRdata('TLSA', '3 1 1 AB CD')).toBe('3 1 1 abcd')
    expect(normalizeRdata('DS', '60485 13 2 AB  CD')).toBe('60485 13 2 abcd')
    expect(normalizeRdata('SSHFP', '4 2 ABCD')).toBe('4 2 abcd')
    expect(normalizeRdata('DNAME', 'New.Example.Lan.')).toBe('new.example.lan.')
    const { errors } = validateForm({ owner: 'old', rtype: 'DNAME', ttl: '300', rdata: 'a.\nb.' }, 'example.lan.')
    expect(errors.rdata).toBe('records.types.errors.singleton')
  })
})
