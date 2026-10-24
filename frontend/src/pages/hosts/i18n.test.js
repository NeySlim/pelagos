// SPDX-License-Identifier: Apache-2.0
// i18n of the DHCP, hosts and nodes areas: en and fr carry the same keys, and every
// literal key the area sources pass to t() resolves in both languages.
import { describe, it, expect } from 'vitest'
import { resources } from '../../i18n'

const NAMESPACES = ['dhcp', 'hosts', 'nodes']
const sources = import.meta.glob(['../dhcp/*.{js,jsx}', '../hosts/*.{js,jsx}', '../nodes/*.{js,jsx}', '!**/*.test.*'], {
  eager: true,
  query: '?raw',
  import: 'default',
})

function lookup(lang, ns, key) {
  return key.split('.').reduce((node, part) => (node && typeof node === 'object' ? node[part] : undefined), resources[lang]?.[ns])
}

function flatKeys(obj, prefix = '') {
  return Object.entries(obj).flatMap(([k, v]) => (v && typeof v === 'object' ? flatKeys(v, `${prefix}${k}.`) : [`${prefix}${k}`]))
}

// Literal t('key') and t('ns:key') calls; the default namespace is the first one the
// file passes to useTranslation.
function usedKeys(source) {
  const defaultNs = source.match(/useTranslation\(\s*\[?\s*'([^']+)'/)?.[1] || 'common'
  return [...source.matchAll(/\bt\(\s*'([^']+)'/g)].map(([, key]) => {
    const at = key.indexOf(':')
    return at > 0 ? { ns: key.slice(0, at), key: key.slice(at + 1) } : { ns: defaultNs, key }
  })
}

// Keys built at runtime from a value, listed here so they stay covered.
const DYNAMIC = [
  ...['start', 'cancel'].flatMap((a) => ['title', 'message'].map((f) => ['dhcp', `ha.confirm.maintenance.${a}.${f}`])),
  ...['true', 'false'].flatMap((a) => ['title', 'message'].map((f) => ['dhcp', `ha.confirm.service.${a}.${f}`])),
  ...['900', '3600', '86400'].map((s) => ['nodes', `enroll.ttlOption.${s}`]),
  ...['bind', 'kea4', 'kea6', 'd2'].map((m) => ['nodes', `modules.${m}`]),
  ['hosts', 'pages.list.title'],
  ['nodes', 'pages.list.title'],
  ...['subnets', 'sharedNetworks', 'options', 'classes', 'leases', 'reservations', 'ha', 'ddns', 'hooks'].flatMap((p) => [
    ['dhcp', `pages.${p}.title`],
    ['dhcp', `pages.${p}.subtitle`],
  ]),
  ...['default', 'declined', 'expired-reclaimed', 'released', 'registered'].map((s) => ['common', `status.${s}`]),
]

describe('DHCP, hosts and nodes translations', () => {
  it.each(NAMESPACES)('%s has the same keys in en and fr', (ns) => {
    expect(flatKeys(resources.fr[ns]).sort()).toEqual(flatKeys(resources.en[ns]).sort())
  })

  it('scans the area sources', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(15)
  })

  it.each(Object.keys(sources))('every literal key of %s exists in en and fr', (path) => {
    const missing = []
    for (const { ns, key } of usedKeys(sources[path])) {
      for (const lang of ['en', 'fr']) {
        if (typeof lookup(lang, ns, key) !== 'string') missing.push(`${lang}/${ns}:${key}`)
      }
    }
    expect(missing).toEqual([])
  })

  it('resolves the keys built at runtime', () => {
    const missing = []
    for (const [ns, key] of DYNAMIC) {
      for (const lang of ['en', 'fr']) if (typeof lookup(lang, ns, key) !== 'string') missing.push(`${lang}/${ns}:${key}`)
    }
    expect(missing).toEqual([])
  })

  it('keeps the French strings translated where English is a sentence', () => {
    for (const ns of NAMESPACES) {
      const same = flatKeys(resources.en[ns]).filter((key) => {
        const en = lookup('en', ns, key)
        return en.split(' ').length > 3 && en === lookup('fr', ns, key)
      })
      expect(same, ns).toEqual([])
    }
  })
})
