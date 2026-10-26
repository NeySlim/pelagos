// SPDX-License-Identifier: Apache-2.0
// Certificate source forms: the PUT body carries only what the source uses and typed secrets;
// client checks match the server's; expiry levels follow the collector's thresholds; every
// literal certs key of these pages exists in both languages.
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../../i18n'
import { checkRows, checkText, expiryLevel, formErrors, formFromSource, sourceBody } from './certsForm'

const DAY = 86400000

describe('certificate source form', () => {
  it('round-trips a stored UCM source without echoing secrets', () => {
    const form = formFromSource({
      source: 'ucm',
      names: ['alias.example.lan'],
      ucm: { url: 'https://ucm.example.lan', ca_id: 3, validity_days: 365, revoke_old: true },
      secrets: { ucm_api_key: true, eab_hmac: false, dns_api_token: false },
    })
    expect(formErrors(form)).toEqual({})
    const body = sourceBody(form)
    expect(body).toEqual({
      source: 'ucm',
      names: ['alias.example.lan'],
      key_type: 'ec-p256',
      mode: 'node',
      ucm: { url: 'https://ucm.example.lan', ca_id: 3, validity_days: 365, revoke_old: true },
    })
    form.secrets.ucm_api_key = 'new-key'
    expect(sourceBody(form, { apply: true })).toMatchObject({ secrets: { ucm_api_key: 'new-key' }, apply: true })
  })

  it('sends the ACME fields of the chosen challenge only', () => {
    const form = formFromSource({}, { cluster: true })
    expect(form.source).toBe('acme')
    form.acme.profile = 'private'
    form.acme.directory_url = 'https://ca.example.lan/acme/acme/directory'
    form.acme.dns.server = '192.0.2.53:53'
    expect(sourceBody(form, { cluster: true }).acme).toEqual({
      profile: 'private',
      challenge: 'dns-01',
      directory_url: 'https://ca.example.lan/acme/acme/directory',
      dns: { method: 'pelagos', server: '192.0.2.53:53' },
    })
    expect(sourceBody(form, { cluster: true }).node_ids).toBe('all')
    form.acme.challenge = 'http-01'
    form.acme.http_port = '8089'
    expect(sourceBody(form).acme).toEqual({ profile: 'private', challenge: 'http-01', http_port: 8089, directory_url: 'https://ca.example.lan/acme/acme/directory' })
    expect(sourceBody({ ...form, source: 'inherit' })).toEqual({ source: 'inherit' })
  })

  it('flags what the server refuses', () => {
    const form = formFromSource({ source: 'acme', acme: { profile: 'custom', directory_url: 'http://x', eab_kid: 'k', dns: { method: 'provider' } } })
    expect(formErrors(form)).toEqual({
      'acme.directory_url': 'https',
      'secrets.dns_api_token': 'required',
      'secrets.eab_hmac': 'required',
    })
    const ucm = formFromSource({ source: 'ucm' })
    expect(formErrors(ucm)).toEqual({ 'ucm.url': 'https', 'ucm.ca_id': 'required', 'secrets.ucm_api_key': 'required' })
  })
})

describe('expiry level', () => {
  const now = Date.parse('2026-10-26T00:00:00Z')
  const cert = (startDays, lifeDays) => ({
    not_before: new Date(now + startDays * DAY).toISOString(),
    not_after: new Date(now + (startDays + lifeDays) * DAY).toISOString(),
  })
  const thresholds = { warning_days: 30, critical_days: 7 }
  it('uses the day thresholds for ordinary certificates', () => {
    expect(expiryLevel(cert(-30, 90), thresholds, now)).toEqual({ level: 'ok', days: 60 })
    expect(expiryLevel(cert(-70, 90), thresholds, now)).toEqual({ level: 'warning', days: 20 })
    expect(expiryLevel(cert(-85, 90), thresholds, now)).toEqual({ level: 'critical', days: 5 })
    expect(expiryLevel(cert(-91, 90), thresholds, now).level).toBe('expired')
    expect(expiryLevel(null, thresholds, now).level).toBe('unknown')
  })
  it('scales to 24 hour certificates', () => {
    expect(expiryLevel(cert(-14 / 24, 1), thresholds, now).level).toBe('ok')
    expect(expiryLevel(cert(-23 / 24, 1), thresholds, now).level).toBe('critical')
  })
})

describe('check rows', () => {
  it('keeps the worst level per check and renders parameters', () => {
    const rows = checkRows({
      checks: [
        { id: 'usage', level: 'ok', message: 'ok', params: {} },
        { id: 'usage', level: 'error', message: 'a CA certificate', params: {} },
        { id: 'names', level: 'warning', message: 'the certificate does not cover {names}', params: { names: ['a.example.lan', 'b'] } },
      ],
    })
    expect(rows.map((r) => [r.id, r.level])).toEqual([['usage', 'error'], ['names', 'warning']])
    expect(checkText(rows[1])).toBe('the certificate does not cover a.example.lan, b')
  })
})

describe('certs i18n', () => {
  const sources = import.meta.glob(['./*.jsx'], { eager: true, query: '?raw', import: 'default' })
  const resolve = (lang, ns, key) => key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), resources[lang][ns])
  it('resolves every literal key of the certificate pages in every language', () => {
    let count = 0
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_.:-]+)'/g)) {
        const [ns, key] = m[1].includes(':') ? m[1].split(':') : ['certs', m[1]]
        for (const { code } of languages) expect(resolve(code, ns, key), `${file}: ${code} ${ns}:${key}`).toBeTypeOf('string')
        count += 1
      }
    }
    expect(count).toBeGreaterThan(50)
  })
})
