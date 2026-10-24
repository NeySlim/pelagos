// SPDX-License-Identifier: Apache-2.0
// The dns namespace has the same keys in every language, and every literal
// t('...') key used by the DNS screens exists in English.
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../i18n'

const NS = 'dns'
const flatKeys = (obj, prefix = '') =>
  Object.entries(obj).flatMap(([k, v]) => (v && typeof v === 'object' ? flatKeys(v, `${prefix}${k}.`) : [`${prefix}${k}`]))
// Literal first arguments of t(...) calls; template keys are checked by the label tests.
const literalKeys = (src) => [...src.matchAll(/\bt\(\s*'([^'$]+)'/g)].map((m) => m[1])
function resolves(lang, key) {
  const [ns, path] = key.includes(':') ? key.split(':') : [NS, key]
  const value = path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), lang[ns])
  return typeof value === 'string'
}

const sources = import.meta.glob(['./*.jsx', './*.js', '!./*.test.*'], { query: '?raw', import: 'default', eager: true })

describe('dns i18n', () => {
  it.each(languages.map((l) => l.code))('%s has exactly the English keys', (lang) => {
    expect(flatKeys(resources[lang][NS]).sort()).toEqual(flatKeys(resources.en[NS]).sort())
  })

  it('resolves every key the DNS screens use', () => {
    const keys = Object.values(sources).flatMap((src) => literalKeys(src))
    expect(keys.length).toBeGreaterThan(50)
    const missing = keys.filter((key) => !resolves(resources.en, key))
    expect(missing).toEqual([])
  })

  it('has a label for every zone kind and editable record type placeholder', async () => {
    const { EDITABLE_TYPES } = await import('./records')
    for (const type of EDITABLE_TYPES) expect(resources.en.dns.editor.placeholder[type], type).toBeTruthy()
    for (const kind of ['primary', 'secondary', 'stub', 'static-stub', 'forward', 'mirror', 'hint', 'redirect']) expect(resources.en.dns.kind[kind], kind).toBeTruthy()
  })
})
