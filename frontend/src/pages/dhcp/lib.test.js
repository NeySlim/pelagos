// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { parseDdnsValue, noteOf, ownerOf, withNote, userContextEntries, haTransitionRows, ipv4InPrefix, defaultReservationSubnet, sameValue, isUnchanged, firstBadPool, optionRowsOf, optionRowsToText, leasesHref, effectiveBounds, keepNull, poolErrorRow } from './lib'

describe('haTransitionRows', () => {
  it('reads Unix seconds and ISO strings, newest first', () => {
    const rows = haTransitionRows([
      { ts: 1792948855, to_state: 'partner-down' },
      { ts: '2026-10-25T17:21:55.000Z', to_state: 'hot-standby' },
      { ts: 1792948000, to_state: 'ready' },
    ])
    expect(rows.map((r) => r.to_state)).toEqual(['hot-standby', 'partner-down', 'ready'])
    expect(rows[1].at).toBe(1792948855000)
    expect(new Date(rows[1].at).getUTCFullYear()).toBe(2026)
    expect(haTransitionRows(undefined)).toEqual([])
  })
})

describe('parseDdnsValue', () => {
  it('refuses an empty value but accepts an explicit empty string', () => {
    expect(parseDdnsValue('ddns-ttl-percent', '')).toEqual({ error: 'form.required' })
    expect(parseDdnsValue('hostname-char-replacement', '  ')).toEqual({ error: 'form.required' })
    expect(parseDdnsValue('hostname-char-replacement', '""')).toEqual({ value: '' })
  })

  it('checks the type of the known parameters', () => {
    expect(parseDdnsValue('ddns-send-updates', 'true')).toEqual({ value: true })
    expect(parseDdnsValue('ddns-send-updates', 'yes')).toEqual({ error: 'form.expectBoolean' })
    expect(parseDdnsValue('ddns-ttl-percent', '0.5')).toEqual({ value: 0.5 })
    expect(parseDdnsValue('ddns-ttl-percent', 'half')).toEqual({ error: 'form.expectNumber' })
    expect(parseDdnsValue('ddns-ttl', '300')).toEqual({ value: 300 })
    expect(parseDdnsValue('ddns-ttl', '1.5')).toEqual({ error: 'form.positiveInteger' })
    expect(parseDdnsValue('ddns-qualifying-suffix', 'example.lan.')).toEqual({ value: 'example.lan.' })
    expect(parseDdnsValue('ddns-qualifying-suffix', '42')).toEqual({ error: 'form.expectString' })
  })

  it('passes unknown parameters through parseScalar', () => {
    expect(parseDdnsValue('ddns-custom', '{"a":1}')).toEqual({ value: { a: 1 } })
  })
})

describe('user-context metadata', () => {
  it('reads notes and owner under "pelagos", and the flat legacy keys', () => {
    expect(noteOf({ pelagos: { notes: 'Desk 7', owner: 'it' } })).toBe('Desk 7')
    expect(ownerOf({ pelagos: { notes: 'Desk 7', owner: 'it' } })).toBe('it')
    expect(noteOf({ 'pelagos:note': 'old' })).toBe('old')
    expect(noteOf(undefined)).toBe('')
  })

  it('writes under "pelagos" and keeps foreign keys', () => {
    const ctx = withNote({ site: 'office', 'pelagos:note': 'old', pelagos: { tags: ['lab'] } }, 'new', 'it')
    expect(ctx).toEqual({ site: 'office', pelagos: { tags: ['lab'], notes: 'new', owner: 'it' } })
    expect(withNote({ pelagos: { notes: 'x' } }, '')).toEqual({})
  })

  it('lists the metadata fields for display', () => {
    expect(userContextEntries({ site: 'a', pelagos: { notes: 'n' } })).toEqual([['site', 'a'], ['pelagos.notes', 'n']])
  })
})

describe('defaultReservationSubnet', () => {
  const subnets = [{ id: 1, subnet: '192.0.2.0/24' }, { id: 7, subnet: '198.51.100.0/25' }]

  it('takes the asked subnet, then the one holding the address, then the filter, then the first', () => {
    expect(defaultReservationSubnet({ prefill: { subnet_id: '7' }, subnets })).toBe('7')
    expect(defaultReservationSubnet({ prefill: { subnet_id: '', ip: '198.51.100.9' }, subnets })).toBe('7')
    expect(defaultReservationSubnet({ prefill: {}, filter: '7', subnets })).toBe('7')
    expect(defaultReservationSubnet({ prefill: {}, filter: '99', subnets })).toBe('1')
    expect(defaultReservationSubnet({ subnets: [] })).toBe('')
  })

  it('checks IPv4 prefixes', () => {
    expect(ipv4InPrefix('198.51.100.127', '198.51.100.0/25')).toBe(true)
    expect(ipv4InPrefix('198.51.100.128', '198.51.100.0/25')).toBe(false)
    expect(ipv4InPrefix('x', '198.51.100.0/25')).toBe(false)
  })
})

describe('unchanged guard helpers', () => {
  it('reads null, undefined and empty alike and ignores key order', () => {
    expect(sameValue({ a: 1, b: null }, { b: undefined, a: 1 })).toBe(true)
    expect(sameValue({ a: [1, { x: '' }] }, { a: [1, {}] })).toBe(true)
    expect(sameValue({ a: 1 }, { a: 2 })).toBe(false)
    expect(sameValue([1], [1, 2])).toBe(false)
  })

  it('is never unchanged for an add', () => {
    expect(isUnchanged(null, { id: 1 })).toBe(false)
    expect(isUnchanged({ id: 1 }, { id: 1 })).toBe(true)
  })

  it('finds the first bad pool row', () => {
    expect(firstBadPool(['192.0.2.1 - 192.0.2.9', ' ', '192.0.2.0/24'], 'v4')).toBeNull()
    expect(firstBadPool(['192.0.2.1 - 192.0.2.9', 'nope'], 'v4')).toEqual({ index: 1, value: 'nope' })
    expect(firstBadPool(['192.0.2.0/33'], 'v4')).toEqual({ index: 0, value: '192.0.2.0/33' })
  })

  it('round-trips option rows', () => {
    const rows = optionRowsOf([{ name: 'routers', data: '192.0.2.1' }, { code: 6, data: '192.0.2.53' }])
    expect(rows).toEqual([{ key: 'routers', value: '192.0.2.1' }, { key: '6', value: '192.0.2.53' }])
    expect(optionRowsToText([...rows, { key: '', value: '' }])).toBe('routers = 192.0.2.1\n6 = 192.0.2.53')
  })

  it('links a pool to its declined leases', () => {
    expect(leasesHref('v4', 3, 'declined')).toBe('/dhcp/v4/leases?subnet_id=3&state=declined')
  })
})

describe('subnet bounds and flags', () => {
  const subnet = { valid_lifetime: 3600, min_valid_lifetime: 3600, max_valid_lifetime: 3600 }
  it('drops bounds that mirror the old default once the default changes', () => {
    expect(effectiveBounds(subnet, { min: 3600, def: 7200, max: 3600 })).toEqual({ min: null, def: 7200, max: null })
    expect(effectiveBounds(subnet, { min: 900, def: 7200, max: 3600 })).toEqual({ min: 900, def: 7200, max: null })
    expect(effectiveBounds(subnet, { min: 3600, def: 3600, max: 3600 })).toEqual({ min: 3600, def: 3600, max: 3600 })
  })
  it('keeps a null flag while the box sits at its default', () => {
    expect(keepNull(null, false, false)).toBeNull()
    expect(keepNull(null, true, false)).toBe(true)
    expect(keepNull(true, true, true)).toBe(true)
  })
  it('finds the pool row of a server error', () => {
    expect(poolErrorRow('after.pools.2.pool')).toBe(2)
    expect(poolErrorRow('pools[1]')).toBe(1)
    expect(poolErrorRow('subnet')).toBeNull()
  })
})
