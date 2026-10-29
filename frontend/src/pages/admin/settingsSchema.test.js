// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import schema from '../../../mock/settingsSchema.json'
import { resources, languages } from '../../i18n'
import {
  sectionsOf, defaultsOf, fieldError, validateSettings, translateLegacy, unknownKeys,
  viewKeyRows, rowsToViewKeys, durationParts, matchesQuery, getPath, setPath,
} from './settingsSchema'

const spec = (key) => schema.settings.find((s) => s.key === key)

describe('settings schema', () => {
  it('groups every setting by domain, then by group', () => {
    const sections = sectionsOf(schema)
    expect(sections.map((s) => s.id)).toEqual(schema.domains)
    const checks = sections.find((s) => s.id === 'checks')
    expect(checks.groups.map((g) => g.id)).toEqual(['pools', 'ddns', 'secondaries', 'ha', 'kea', 'clock', 'certificates', 'api_tokens', 'disk', 'resolver', 'delegation', 'soa', 'advisories', 'notifications', 'archives'])
    expect(sections.flatMap((s) => s.groups.flatMap((g) => g.fields)).length).toBe(schema.settings.length)
  })

  it('has defaults that pass every rule and no leaf at the root', () => {
    const defaults = defaultsOf(schema)
    expect(Object.values(defaults).every((v) => v && typeof v === 'object')).toBe(true)
    expect(validateSettings(schema, defaults)).toEqual({})
  })

  it('checks types, bounds, names and URLs', () => {
    expect(fieldError(spec('checks.pool_warning_percent'), 0)).toEqual({ code: 'range', params: { min: 1, max: 100 } })
    expect(fieldError(spec('checks.pool_warning_percent'), 'abc')).toEqual({ code: 'number' })
    expect(fieldError(spec('checks.pool_warning_percent'), 4.5)).toEqual({ code: 'integer' })
    expect(fieldError(spec('checks.d2_error_percent'), 2.5)).toBe(null)
    expect(fieldError(spec('dns.read_key'), 'bad key')).toEqual({ code: 'name' })
    expect(fieldError(spec('archives.start_time'), '24:00')).toEqual({ code: 'time' })
    expect(fieldError(spec('archives.start_time'), '03:15')).toBeNull()
    expect(fieldError(spec('dns.read_key'), '')).toEqual({ code: 'required' })
    expect(fieldError(spec('checks.advisories_url'), 'http://example.net')).toEqual({ code: 'https' })
    expect(fieldError(spec('checks.advisories_url'), '')).toBe(null)
    expect(fieldError(spec('dns.update_types_kea'), ['A', 'ptr'])).toEqual({ code: 'item', params: { item: 'ptr' } })
    expect(fieldError(spec('auth.require_totp'), 'yes')).toEqual({ code: 'boolean' })
  })

  it('keeps warning and critical in order', () => {
    let s = setPath(defaultsOf(schema), 'checks.pool_warning_percent', 96)
    expect(validateSettings(schema, s)).toEqual({ 'checks.pool_warning_percent': { code: 'lower', params: { other: 'checks.pool_critical_percent' } } })
    s = setPath(defaultsOf(schema), 'checks.cert_critical_days', 30)
    expect(Object.keys(validateSettings(schema, s))).toEqual(['checks.cert_critical_days'])
    s = setPath(defaultsOf(schema), 'auth.session_idle_seconds', 43200)
    expect(validateSettings(schema, s)).toEqual({}) // at most, not strictly lower
  })

  it('edits view keys as rows', () => {
    const map = { inside: 'ddi-inside', guest: { admin: 'g-admin', read: 'g-read' } }
    const rows = viewKeyRows(map)
    expect(rows).toEqual([{ view: 'inside', admin: 'ddi-inside', read: '' }, { view: 'guest', admin: 'g-admin', read: 'g-read' }])
    expect(rowsToViewKeys([...rows, { view: ' ', admin: '', read: '' }])).toEqual(map)
    expect(fieldError(spec('dns.view_keys'), { _default: 'x' })).toEqual({ code: 'viewName', params: { view: '_default' } })
    expect(fieldError(spec('dns.view_keys'), { inside: '' })).toEqual({ code: 'viewKey', params: { view: 'inside' } })
  })

  it('moves former names to the current ones', () => {
    expect(translateLegacy(schema, { alerts_d2_error_rate: 0.05, plan_ttl_seconds: 900 })).toEqual({ checks: { d2_error_percent: 5 }, plans: { ttl_seconds: 900 } })
    expect(unknownKeys(schema, { checks: { nope: 1 }, rpz: { categories: {} }, plans: { ttl_seconds: 1 } })).toEqual(['checks.nope', 'rpz.categories'])
  })

  it('shows durations and finds settings', () => {
    expect(durationParts(43200, 'seconds')).toEqual([12, 'hours'])
    expect(durationParts(90, 'days')).toBe(null)
    expect(durationParts(1800, 'seconds')).toEqual([30, 'minutes'])
    expect(matchesQuery(spec('checks.ha_grace_seconds'), 'HA alert grace period', 'grace')).toBe(true)
    expect(matchesQuery(spec('checks.ha_grace_seconds'), 'HA alert grace period', 'rpz')).toBe(false)
    expect(matchesQuery(spec('checks.custom_hooks_enabled'), ['Warn about Kea hooks'], 'custom hooks')).toBe(true)
    expect(getPath({ a: { b: 1 } }, 'a.b')).toBe(1)
  })

  it('labels every setting, section, group and unit in every language', () => {
    for (const { code } of languages) {
      const s = resources[code].admin.settings
      for (const item of schema.settings) {
        expect(getPath(s.fields, item.key), `${code} ${item.key}`).toBeTypeOf('string')
        if (item.unit) expect(s.units[item.unit], `${code} unit ${item.unit}`).toBeTypeOf('string')
        if (item.group) expect(s.groups[item.group], `${code} group ${item.group}`).toBeTypeOf('string')
      }
      for (const domain of schema.domains) expect(s.sections[domain]?.title, `${code} ${domain}`).toBeTypeOf('string')
    }
  })
})
