// SPDX-License-Identifier: Apache-2.0
// The dashboard namespace has the same keys in every language, every literal
// t('...') key used by the tiles exists in English, and every alert kind of
// architecture section 15 has a label.
import { describe, it, expect } from 'vitest'
import { resources, languages } from '../../i18n'
import { TILE_IDS } from './layout'

const NS = 'dashboard'
const flatKeys = (obj, prefix = '') =>
  Object.entries(obj).flatMap(([k, v]) => (v && typeof v === 'object' ? flatKeys(v, `${prefix}${k}.`) : [`${prefix}${k}`]))
const literalKeys = (src) => [...src.matchAll(/\bt\(\s*'([^'$]+)'/g)].map((m) => m[1])
// A counted key resolves through its plural forms (`<key>_one`, `<key>_other`).
function resolves(lang, key) {
  const [ns, path] = key.includes(':') ? key.split(':') : [NS, key]
  const get = (p) => p.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), lang[ns])
  return typeof get(path) === 'string' || (typeof get(`${path}_one`) === 'string' && typeof get(`${path}_other`) === 'string')
}

const sources = import.meta.glob(['./*.jsx', './*.js', '!./*.test.*'], { query: '?raw', import: 'default', eager: true })

const ALERT_KINDS = [
  'pool_near_full', 'pool_full', 'serial_divergence', 'secondary_stale', 'zone_error', 'ha_degraded', 'ha_partner_down',
  'ha_transition', 'd2_errors', 'daemon_down', 'peer_offline', 'config_divergence', 'lease_without_record',
  'record_without_lease', 'reservation_mismatch', 'ptr_mismatch', 'duplicate_ip', 'insecure_key', 'insecure_listener',
]

describe('dashboard i18n', () => {
  it.each(languages.map((l) => l.code))('%s has exactly the English keys', (lang) => {
    expect(flatKeys(resources[lang][NS]).sort()).toEqual(flatKeys(resources.en[NS]).sort())
  })

  it('resolves every key the dashboard uses', () => {
    const keys = Object.values(sources).flatMap((src) => literalKeys(src))
    expect(keys.length).toBeGreaterThan(20)
    expect(keys.filter((key) => !resolves(resources.en, key))).toEqual([])
  })

  it('labels every tile and every alert kind', () => {
    for (const id of TILE_IDS) expect(resources.en[NS].tiles[id]?.title, id).toBeTruthy()
    for (const kind of ALERT_KINDS) expect(resources.en[NS].kinds[kind], kind).toBeTruthy()
  })
})
