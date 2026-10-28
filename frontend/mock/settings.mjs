// SPDX-License-Identifier: Apache-2.0
// Cluster settings of the mock: the schema is the backend registry's own export
// (settingsSchema.json, `make settings-schema`), validated like PUT /admin/settings.
import { readFileSync } from 'node:fs'
import { defaultsOf, translateLegacy, unknownKeys, validateSettings } from '../src/pages/admin/settingsSchema.js'

export const SETTINGS_SCHEMA = JSON.parse(readFileSync(new URL('./settingsSchema.json', import.meta.url), 'utf8'))

const MANAGED = { rpz: ['categories', 'subscriptions', 'order', 'allow', 'exempt_clients'], certificates: ['cluster', 'nodes'] }

export function makeSettings() {
  return defaultsOf(SETTINGS_SCHEMA)
}

export function setting(state, key) {
  return key.split('.').reduce((acc, k) => (acc == null ? undefined : acc[k]), state.settings)
}

// A map setting (dns.view_keys) is replaced whole, like core.settings_registry.merge.
const MAPS = new Set(SETTINGS_SCHEMA.settings.filter((s) => s.type === 'map').map((s) => s.key))
const merge = (target, patch, prefix = '') => {
  const out = { ...target }
  for (const [k, v] of Object.entries(patch)) {
    const key = prefix ? `${prefix}.${k}` : k
    out[k] = v && typeof v === 'object' && !Array.isArray(v) && !MAPS.has(key) ? merge(out[k] && typeof out[k] === 'object' ? out[k] : {}, v, key) : v
  }
  return out
}

const MESSAGES = {
  boolean: () => 'boolean expected',
  number: () => 'number expected',
  integer: () => 'integer expected',
  range: (p) => `must be between ${p.min} and ${p.max}`,
  required: () => 'non-empty string expected',
  name: () => 'invalid name',
  time: () => 'HH:MM expected',
  https: () => 'https URL expected',
  list: () => 'list of strings expected',
  item: (p) => `invalid item: ${p.item}`,
  object: () => 'object expected',
  viewName: (p) => `invalid view name: ${p.view}`,
  viewKey: (p) => `view ${p.view}: a key name or {admin, read} expected`,
  lower: (p) => `must be lower than ${p.other}`,
  atMost: (p) => `must be at most ${p.other}`,
}

// PUT /admin/settings: partial body, former names accepted; returns the merged settings or throws.
export function updateSettings(state, rawBody, invalidMany) {
  const body = translateLegacy(SETTINGS_SCHEMA, rawBody)
  const errors = unknownKeys(SETTINGS_SCHEMA, body).map((field) => {
    const [domain, leaf] = field.split('.')
    return { field, message: MANAGED[domain]?.includes(leaf) ? 'set through its own screen' : 'unknown setting' }
  })
  const merged = merge(state.settings, body)
  const checked = validateSettings(SETTINGS_SCHEMA, merged)
  for (const [field, err] of Object.entries(checked)) errors.push({ field, message: MESSAGES[err.code]?.(err.params || {}) || err.code })
  if (errors.length) throw invalidMany(errors)
  state.settings = merged
  return { settings: merged, body }
}
