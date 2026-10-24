// SPDX-License-Identifier: Apache-2.0
// Every namespace exists in every language with exactly the same keys, and every
// label the navigation and the area pages use resolves in each language.
import { describe, it, expect } from 'vitest'
import i18n, { resources, languages } from './index'
import { allNavItems, navGroups, allRoutes } from '../pages/routes'

// Paths as arrays: some keys contain dots themselves (plan.scope["dns.rrset"]).
function flatPaths(obj, prefix = []) {
  return Object.entries(obj).flatMap(([k, v]) =>
    v && typeof v === 'object' && !Array.isArray(v) ? flatPaths(v, [...prefix, k]) : [[...prefix, k]],
  )
}
const flatKeys = (obj) => flatPaths(obj).map((p) => JSON.stringify(p))

function placeholders(text) {
  return [...String(text).matchAll(/\{\{\s*(\w+)\s*\}\}/g)].map((m) => m[1]).sort()
}

describe('i18n resources', () => {
  const codes = languages.map((l) => l.code)
  const namespaces = Object.keys(resources.en)

  it('has en and fr with the same namespaces', () => {
    expect(codes).toEqual(['en', 'fr'])
    for (const lang of codes) expect(Object.keys(resources[lang]).sort()).toEqual([...namespaces].sort())
  })

  it.each(namespaces)('namespace %s has the same keys and placeholders in every language', (ns) => {
    const reference = flatKeys(resources.en[ns]).sort()
    for (const lang of codes) {
      const keys = flatKeys(resources[lang][ns]).sort()
      expect(keys, `${lang}/${ns}.json`).toEqual(reference)
      for (const key of reference) {
        const get = (l) => JSON.parse(key).reduce((o, k) => o[k], resources[l][ns])
        expect(placeholders(get(lang)), `${lang}/${ns}.json ${key}`).toEqual(placeholders(get('en')))
        expect(String(get(lang)).trim(), `${lang}/${ns}.json ${key} is empty`).not.toBe('')
        expect(String(get(lang)), `${lang}/${ns}.json ${key} has an em dash`).not.toContain(String.fromCharCode(0x2014))
      }
    }
  })

  it.each(codes)('resolves every navigation label in %s', (lang) => {
    const t = i18n.getFixedT(lang, 'common')
    for (const item of allNavItems) expect(i18n.exists(item.labelKey, { lng: lang, ns: 'common' }), item.labelKey).toBe(true)
    for (const group of navGroups) expect(t(group.labelKey)).not.toBe(group.labelKey)
  })

  it('gives every area a namespace', () => {
    const areas = new Set(allRoutes.map((r) => r.area))
    for (const area of areas) expect(namespaces, area).toContain(area)
  })
})
