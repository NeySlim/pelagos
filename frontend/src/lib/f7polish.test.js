// SPDX-License-Identifier: Apache-2.0
// Item 81 polish: page titles, locale sizes and threshold numbers, translated role descriptions,
// shared certificate source, notification language and translated validation errors.
import { describe, it, expect, afterEach } from 'vitest'
import i18n from '../i18n'
import { pageTitle } from '../pages/routes'
import { formatSize } from './utils'
import { formatThreshold } from '../pages/dns/resolverHealth'
import { formatMb } from '../pages/dns/rpzHelpers'
import { roleDescription } from '../pages/admin/validation'
import { commonNodeSource } from '../pages/admin/certs/certsForm'
import { formFromChannel } from '../pages/admin/notifications/notifyForm'
import { ApiError, errorItemText, errorMessage } from '../services/apiClient'

afterEach(() => i18n.changeLanguage('en'))

describe('page title', () => {
  it('names the page before the product', async () => {
    await i18n.changeLanguage('fr')
    const t = i18n.t.bind(i18n)
    expect(pageTitle('/', t)).toBe('Tableau de bord · Pelagos')
    expect(pageTitle('/dns/zones/example.lan.', t)).toMatch(/^Zones · Pelagos$/)
    expect(pageTitle('/nowhere/at/all', t)).toBe('Pelagos')
  })
})

describe('numbers and sizes in the UI language', () => {
  it('formats sizes with French units and decimal comma', async () => {
    expect(formatMb(1520)).toBe('1.5 GB')
    await i18n.changeLanguage('fr')
    expect(formatMb(5900)).toBe('5,9 Go')
    expect(formatMb(94.4)).toBe('94 Mo')
    expect(formatSize(48_000)).toBe('48 ko')
  })

  it('formats thresholds with the precision of the readings', () => {
    expect(formatThreshold(107.229, 'fr')).toBe('107')
    expect(formatThreshold(0.275, 'fr')).toBe('0,28')
    expect(formatThreshold(91.8, 'fr')).toBe('91,8')
    expect(formatThreshold(1600, 'en')).toBe('1600')
    expect(formatThreshold(null, 'en')).toBe('-')
  })
})

describe('built-in roles', () => {
  it('translates built-in descriptions and keeps custom ones', async () => {
    await i18n.changeLanguage('fr')
    const t = i18n.t.bind(i18n)
    expect(roleDescription({ name: 'admin', builtin: true, description: 'Everything' }, t)).toBe('Toutes les permissions')
    expect(roleDescription({ name: 'viewer', builtin: true, description: 'Read everything except secrets' }, t)).toBe('Lecture de tout sauf les secrets')
    expect(roleDescription({ name: 'ops', builtin: false, description: 'Night shift' }, t)).toBe('Night shift')
  })
})

describe('shared certificate source', () => {
  const ucm = (names) => ({ source: 'ucm', names, ucm: { url: 'https://ucm.example.lan', ca_id: 3 }, secrets: { ucm_api_key: true } })
  it('offers the source every node uses on its own', () => {
    const src = commonNodeSource([{ node_id: 'a', source: ucm(['ns1.example.lan']) }, { node_id: 'b', source: ucm(['ns2.example.lan']) }])
    expect(src).toMatchObject({ source: 'ucm', ucm: { url: 'https://ucm.example.lan' } })
    expect(src.secrets).toBeUndefined()
    expect(src.names).toBeUndefined()
  })
  it('offers nothing when the nodes differ or inherit', () => {
    const other = { ...ucm([]), ucm: { url: 'https://other.example.lan', ca_id: 3 } }
    expect(commonNodeSource([{ source: ucm([]) }, { source: other }])).toBeNull()
    expect(commonNodeSource([{ source: ucm([]) }, { source: ucm([]), inherited: true }])).toBeNull()
    expect(commonNodeSource([{ source: { source: 'self_signed' } }, { source: { source: 'self_signed' } }])).toBeNull()
    expect(commonNodeSource([{ source: ucm([]) }])).toBeNull()
  })
})

describe('notification channel language', () => {
  it('defaults a new channel to the UI language and keeps a stored one', () => {
    expect(formFromChannel({}, 'ntfy', 'fr').language).toBe('fr')
    expect(formFromChannel({}, 'ntfy', 'de').language).toBe('en')
    expect(formFromChannel({ language: 'en' }, 'ntfy', 'fr').language).toBe('en')
  })
})

describe('validation error items', () => {
  it('renders the translated output of a record check', async () => {
    await i18n.changeLanguage('fr')
    const item = {
      tool: 'dnspython',
      message: "invalid A rdata '999.1.1.1': Text input is malformed.",
      message_message: { key: 'common.text', params: { text: { join: [{ key: 'rrset.invalid_rdata', params: { rtype: 'A', value: '999.1.1.1' } }], sep: '\n' } } },
    }
    expect(errorItemText(item)).toBe("999.1.1.1 n'est pas une valeur A valide")
    const err = new ApiError('dnspython rejected the change', {
      status: 422,
      code: 'engine_validation_failed',
      problem: { detail_message: { key: 'problem.detail.engine_rejected', params: { tool: 'dnspython' } } },
      errors: [item],
    })
    expect(errorMessage(err)).toBe("dnspython a refusé la modification: 999.1.1.1 n'est pas une valeur A valide")
  })
})
