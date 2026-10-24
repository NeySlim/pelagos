// SPDX-License-Identifier: Apache-2.0
// The audit, advanced, install, admin and account namespaces: same keys in every
// language, and every literal key their pages pass to t() resolves in each one.
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../i18n'

const AREAS = ['audit', 'advanced', 'install', 'admin', 'account']
const sources = import.meta.glob(['/src/pages/{audit,advanced,install,admin,account}/*.{js,jsx}', '!/src/pages/**/*.test.*'], { eager: true, query: '?raw', import: 'default' })

function flatKeys(obj, prefix = '') {
  return Object.entries(obj).flatMap(([k, v]) => (v && typeof v === 'object' ? flatKeys(v, `${prefix}${k}.`) : [`${prefix}${k}`]))
}

function resolve(lang, ns, key) {
  const node = key.split('.').reduce((o, k) => (o == null ? undefined : o[k]), resources[lang][ns])
  if (typeof node === 'string') return node
  // Plural forms: key_one / key_other.
  const parts = key.split('.')
  const last = parts.pop()
  const parent = parts.reduce((o, k) => (o == null ? undefined : o[k]), resources[lang][ns])
  return parent?.[`${last}_other`]
}

// Literal keys of t('...') calls with the area namespace as default.
function literalKeys(area) {
  const out = []
  for (const [path, text] of Object.entries(sources)) {
    if (!path.startsWith(`/src/pages/${area}/`)) continue
    for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_.:-]+)'/g)) {
      const raw = m[1]
      const [ns, key] = raw.includes(':') ? raw.split(':') : [area, raw]
      out.push({ file: path, ns, key })
    }
  }
  return out
}

describe('admin areas i18n', () => {
  const codes = languages.map((l) => l.code)

  it.each(AREAS)('%s has the same keys in every language', (area) => {
    const reference = flatKeys(resources.en[area]).sort()
    expect(reference.length).toBeGreaterThan(3)
    for (const lang of codes) expect(flatKeys(resources[lang][area]).sort(), `${lang}/${area}`).toEqual(reference)
  })

  it.each(AREAS)('every literal key used by the %s pages exists', (area) => {
    const keys = literalKeys(area)
    expect(keys.length, `no t() call found in ${area}`).toBeGreaterThan(3)
    for (const { file, ns, key } of keys) {
      for (const lang of codes) {
        // Pages load [area, 'common']: an unprefixed key may come from common.
        const found = resolve(lang, ns, key) ?? (ns === area ? resolve(lang, 'common', key) : undefined)
        expect(found, `${file}: ${lang} ${ns}:${key}`).toBeTypeOf('string')
      }
    }
  })

  it('French strings are translated, not copied, where they are sentences', () => {
    for (const area of AREAS) {
      const en = flatKeys(resources.en[area])
      const same = en.filter((k) => {
        const a = resolve('en', area, k)
        return a.split(' ').length > 3 && a === resolve('fr', area, k)
      })
      expect(same, area).toEqual([])
    }
  })
})
