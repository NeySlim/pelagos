// SPDX-License-Identifier: Apache-2.0
// Every key the backend can emit (backendMessageKeys.json, generated from
// pelagos.domain.messages.CATALOG) exists in each language with exactly its parameters,
// and renderMessage falls back to the backend's English text when it cannot translate.
import { afterEach, describe, it, expect } from 'vitest'
import i18n, { resources, languages } from './index'
import backendKeys from './backendMessageKeys.json'
import { renderMessage, MESSAGES_NS } from './message'
import { ApiError, errorMessage } from '../services/apiClient'

function placeholders(text) {
  return [...new Set([...String(text).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]))].sort()
}

describe('backend message catalog', () => {
  const keys = Object.keys(backendKeys)

  it('is not empty and covers every area', () => {
    for (const prefix of ['plan.', 'alert.', 'finding.', 'job.step.', 'problem.']) {
      expect(keys.some((k) => k.startsWith(prefix)), prefix).toBe(true)
    }
  })

  it.each(languages.map((l) => l.code))('has every backend key with its parameters in %s', (lang) => {
    const catalog = resources[lang][MESSAGES_NS]
    for (const key of keys) {
      expect(typeof catalog[key], `${lang}/messages.json ${key}`).toBe('string')
      expect(placeholders(catalog[key]), `${lang}/messages.json ${key}`).toEqual(backendKeys[key])
    }
  })

  it('has no key the backend does not emit, plural forms of a counted key aside', () => {
    const plural = /^(.+)_(zero|one|two|few|many|other)$/
    for (const lang of languages.map((l) => l.code)) {
      const own = Object.keys(resources[lang][MESSAGES_NS])
      const base = own.filter((k) => !(plural.test(k) && backendKeys[k.match(plural)[1]]?.includes('count')))
      expect(base.sort(), lang).toEqual([...keys].sort())
      for (const k of own.filter((k) => !base.includes(k))) expect(placeholders(resources[lang][MESSAGES_NS][k]), k).toEqual(backendKeys[k.match(plural)[1]])
    }
  })
})

describe('renderMessage', () => {
  afterEach(() => i18n.changeLanguage('en'))

  const summary = {
    key: 'plan.rrset.counts',
    params: {
      zone: 'example.lan.',
      counts: [
        { key: 'plan.rrset.count', params: { count: 1, op: { key: 'op.add', params: {} } } },
        { key: 'plan.rrset.count', params: { count: 2, op: { key: 'op.delete', params: {} } } },
      ],
    },
  }

  it('renders nested messages and lists like the backend', () => {
    expect(renderMessage(summary, 'x')).toBe('example.lan.: 1 add, 2 delete')
  })

  it('translates into French', async () => {
    await i18n.changeLanguage('fr')
    expect(renderMessage(summary, 'x')).toBe('example.lan. : ajout : 1, suppression : 2')
    const alert = { key: 'alert.ha_partner_down', params: { engine: 'kea4', state: 'partner-down' } }
    expect(renderMessage(alert, 'x')).toBe('Le partenaire HA kea4 est arrêté (état partner-down)')
  })

  it('joins with the separator the backend chose', () => {
    const m = {
      key: 'alert.ptr_mismatch',
      params: {
        ip: '192.0.2.10',
        problems: {
          join: [
            { key: 'alert.ptr_mismatch.no_ptr', params: { name: 'a.example.lan.', found: { key: 'common.none', params: {} } } },
            { key: 'alert.ptr_mismatch.dangling', params: { target: 'b.example.lan.' } },
          ],
          sep: '; ',
        },
      },
    }
    expect(renderMessage(m)).toBe(
      '192.0.2.10: a.example.lan. has no PTR (found none); PTR points to b.example.lan. which has no address record for it',
    )
  })

  it('picks the plural form from a numeric count', async () => {
    expect(renderMessage({ key: 'plan.security', params: { count: 3 } })).toBe('security remediation: 3 findings')
    expect(renderMessage({ key: 'plan.security', params: { count: 1 } })).toBe('security remediation: 1 finding')
    await i18n.changeLanguage('fr')
    expect(renderMessage({ key: 'note.secret_files', params: { count: 2 } })).toBe('2 fichiers secrets')
    expect(renderMessage({ key: 'note.secret_files', params: { count: 1 } })).toBe('1 fichier secret')
    // A count given as text stays a plain parameter: the base key renders.
    expect(renderMessage({ key: 'plan.security', params: { count: '4' } })).toBe('correction de sécurité : 4 constats')
  })

  it('falls back to the English text for unknown keys, nested ones included', () => {
    expect(renderMessage({ key: 'plan.from_a_newer_backend', params: {} }, 'fallback text')).toBe('fallback text')
    const nested = { key: 'common.with_note', params: { text: 'a', note: { key: 'note.unknown', params: {} } } }
    expect(renderMessage(nested, 'a (b)')).toBe('a (b)')
    expect(renderMessage(null, 'plain')).toBe('plain')
    expect(renderMessage('not a message', 'plain')).toBe('plain')
  })

  it('does not escape HTML-looking parameters twice', () => {
    expect(renderMessage({ key: 'plan.host', params: { fqdn: 'a&b.example.lan.', ip: '192.0.2.1' } })).toBe(
      'host a&b.example.lan. -> 192.0.2.1',
    )
  })
})

describe('errorMessage', () => {
  afterEach(() => i18n.changeLanguage('en'))

  it('translates a problem detail that carries a message key', async () => {
    const problem = {
      code: 'plan_expired',
      title: 'Plan expired',
      detail: 'Plan expired',
      title_message: { key: 'problem.plan_expired', params: {} },
      detail_message: { key: 'problem.plan_expired', params: {} },
    }
    const err = new ApiError('Plan expired', { status: 410, code: 'plan_expired', problem })
    expect(errorMessage(err)).toBe('Plan expired')
    await i18n.changeLanguage('fr')
    expect(errorMessage(err)).toBe('Plan expiré')
  })

  it('keeps a free-text detail as it is', async () => {
    await i18n.changeLanguage('fr')
    const problem = { code: 'conflict', detail: 'subnet 7 already exists', title_message: { key: 'problem.conflict', params: {} } }
    expect(errorMessage(new ApiError('subnet 7 already exists', { status: 409, problem }))).toBe('subnet 7 already exists')
  })
})
