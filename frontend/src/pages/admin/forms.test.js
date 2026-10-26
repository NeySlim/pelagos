// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { diffPatch, setIn, getIn, parseNumber, setClusterModule, modulesPatch } from './settingsForm'
import { passwordProblem, fieldErrors, groupPermissions, USERNAME_RE } from './validation'

describe('settings form', () => {
  const settings = { auth: { require_totp: false }, plans: { ttl_seconds: 600 }, dns: { read_key: 'ddi-read', update_types_kea: ['A', 'PTR'] }, retention: { backups_days: 90 } }

  it('sends only what changed', () => {
    expect(diffPatch(settings, settings)).toBe(null)
    const edited = setIn(setIn(settings, ['retention', 'backups_days'], 30), ['auth', 'require_totp'], true)
    expect(getIn(edited, ['retention', 'backups_days'])).toBe(30)
    expect(settings.retention.backups_days).toBe(90)
    expect(diffPatch(settings, edited)).toEqual({ auth: { require_totp: true }, retention: { backups_days: 30 } })
    expect(diffPatch(settings, setIn(settings, ['dns', 'update_types_kea'], ['A']))).toEqual({ dns: { update_types_kea: ['A'] } })
  })

  it('patches module switches per node', () => {
    const before = { cluster: { dhcpv6: true, advanced_editor: true }, nodes: { n1: { bind: true, kea4: true }, n2: { bind: true, kea4: false } } }
    const after = setIn(before, ['nodes', 'n2', 'kea4'], true)
    expect(diffPatch(before, after)).toEqual({ nodes: { n2: { kea4: true } } })
  })

  it('parses numbers by type', () => {
    expect(parseNumber('integer', '42')).toBe(42)
    expect(parseNumber('integer', '4.2')).toBe(null)
    expect(parseNumber('number', '0.05')).toBe(0.05)
    expect(parseNumber('number', '')).toBe(null)
  })
})

describe('admin validation', () => {
  it('checks usernames and passwords', () => {
    expect(USERNAME_RE.test('alice.ops')).toBe(true)
    expect(USERNAME_RE.test('Alice')).toBe(false)
    expect(passwordProblem('short1A')).toBe('passwordShort')
    expect(passwordProblem('alllowercaseletters')).toBe('passwordClasses')
    expect(passwordProblem('Correct-horse-42')).toBe(null)
  })

  it('maps problem document errors to fields', () => {
    expect(fieldErrors({ errors: [{ field: 'username', message: 'taken' }, { message: 'other' }] })).toEqual({ username: 'taken' })
    expect(fieldErrors(null)).toEqual({})
  })

  it('groups permissions by resource family', () => {
    const groups = groupPermissions(['read:dns', 'write:dns.records', 'read:dhcp', 'admin:users'])
    expect(groups).toEqual([
      { family: 'dns', items: ['read:dns', 'write:dns.records'] },
      { family: 'dhcp', items: ['read:dhcp'] },
      { family: 'users', items: ['admin:users'] },
    ])
  })
})

describe('cluster modules', () => {
  it('turns kea6 off on every node with dhcpv6', () => {
    const before = { cluster: { dhcpv6: true, advanced_editor: false }, nodes: { n1: { bind: true, kea4: true, kea6: true, d2: true }, n2: { bind: true, kea4: false, kea6: false, d2: false } } }
    const after = setClusterModule(before, 'dhcpv6', false)
    expect(after.cluster.dhcpv6).toBe(false)
    expect(after.nodes.n1.kea6).toBe(false)
    expect(before.nodes.n1.kea6).toBe(true)
    expect(modulesPatch(before, after)).toEqual({ cluster: { dhcpv6: false }, nodes: { n1: { kea6: false } } })
    expect(setClusterModule(before, 'advanced_editor', true).nodes).toBe(before.nodes)
  })
})
