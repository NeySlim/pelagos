// SPDX-License-Identifier: Apache-2.0
// IPv6 sources form: local checks, the whole-list PUT body with write-only secrets, the test
// body that reuses stored secrets, prefixes and server field errors.
import { describe, it, expect } from 'vitest'
import { formErrors, formFromSource, prefixProblem, removeBody, serverFieldErrors, sourcesBody, testBody, toggleBody } from './ipv6Form'

const stored = { id: 'S1', type: 'opnsense', name: 'Router', url: 'https://router.example.lan', verify_tls: true, ca_pem: null, enabled: true, allow_http: false, exclude_macs: ['02:00:5e:00:53:01'], secrets: { api_key: true, api_secret: true } }
const other = { ...stored, id: 'S2', name: 'Lab', url: 'https://lab.example.lan', exclude_macs: [] }

describe('ipv6Form', () => {
  it('requires a name, an https URL and both secrets for a new source', () => {
    const form = formFromSource({})
    expect(formErrors(form)).toEqual({ name: 'required', url: 'required', 'secrets.api_key': 'secret', 'secrets.api_secret': 'secret' })
    expect(formErrors({ ...form, name: 'R', url: 'http://router.example.lan', secrets: { api_key: 'k', api_secret: 's' } })).toEqual({ url: 'http' })
    expect(formErrors({ ...form, name: 'R', url: 'http://router.example.lan', allow_http: true, secrets: { api_key: 'k', api_secret: 's' } })).toEqual({})
    expect(formErrors({ ...form, name: 'R', url: 'https://r', exclude_macs: 'nope', secrets: { api_key: 'k', api_secret: 's' } })).toEqual({ exclude_macs: 'mac' })
  })

  it('keeps stored secrets unless the URL changes', () => {
    const form = formFromSource(stored)
    expect(formErrors(form)).toEqual({})
    expect(formErrors({ ...form, url: 'https://new.example.lan' })).toEqual({ 'secrets.api_key': 'secret', 'secrets.api_secret': 'secret' })
  })

  it('replaces the list whole, sending only typed secrets of the edited source', () => {
    const form = { ...formFromSource(stored), name: 'Edge', secrets: { api_key: 'newkey', api_secret: '' } }
    const body = sourcesBody([stored, other], form)
    expect(body.sources.map((s) => s.id)).toEqual(['S1', 'S2'])
    expect(body.sources[0]).toMatchObject({ name: 'Edge', secrets: { api_key: 'newkey' }, exclude_macs: ['02:00:5e:00:53:01'] })
    expect(body.sources[1].secrets).toBeUndefined()
    const added = sourcesBody([stored], { ...formFromSource({}), name: 'New', url: 'https://n.example.lan', exclude_macs: '02-00-5E-00-53-02', secrets: { api_key: 'k', api_secret: 's' } })
    expect(added.sources[1]).toEqual({ type: 'opnsense', name: 'New', url: 'https://n.example.lan', verify_tls: true, allow_http: false, ca_pem: null, enabled: true, exclude_macs: ['02:00:5e:00:53:02'], secrets: { api_key: 'k', api_secret: 's' } })
    expect(removeBody([stored, other], 'S1').sources.map((s) => s.id)).toEqual(['S2'])
    expect(toggleBody([stored, other], 'S2', false).sources.map((s) => s.enabled)).toEqual([true, false])
  })

  it('tests an unsaved edit with the saved id as scope', () => {
    const body = testBody({ ...formFromSource(stored), secrets: { api_key: '', api_secret: 'typed' } })
    expect(body).toMatchObject({ scope: 'S1', url: 'https://router.example.lan', secrets: { api_secret: 'typed' } })
    expect(body.id).toBeUndefined()
    expect(testBody(formFromSource({ name: 'x', url: 'https://x' })).scope).toBeUndefined()
  })

  it('checks watched prefixes', () => {
    expect(prefixProblem('2001:db8:1::/64')).toBeNull()
    expect(prefixProblem('fd00:1::/48')).toBeNull()
    expect(prefixProblem('2001:db8::')).toBe('format')
    expect(prefixProblem('192.0.2.0/24')).toBe('format')
    expect(prefixProblem('fe80::/10')).toBe('scope')
    expect(prefixProblem('ff02::/16')).toBe('scope')
  })

  it('maps server field errors of the edited source', () => {
    const errors = [{ field: 'sources[1].url', message: 'bad' }, { field: 'sources[0].name', message: 'other' }, { field: 'source.ca_pem', message: 'pem' }]
    expect(serverFieldErrors(errors, 1)).toEqual({ url: 'bad', ca_pem: 'pem' })
  })
})
