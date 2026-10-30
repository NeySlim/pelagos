// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { parseDdnsValue, noteOf, ownerOf, withNote, userContextEntries, haTransitionRows, ipv4InPrefix, defaultReservationSubnet } from './lib'

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
