// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { parseDdnsValue, noteOf, ownerOf, withNote, userContextEntries } from './lib'

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
