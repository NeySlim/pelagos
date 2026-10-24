// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { addStatement, buildChanges, canAddInside, canAddTop, editableAt, removeStatement, topContext } from './bindGrammar'

const files = () => [
  { path: '/etc/bind/named.conf', managed: false, statements: [
    { name: 'options', value: null, line: 1, children: [{ name: 'recursion', value: 'no', line: 2 }] },
    { name: 'logging', value: null, line: 4, children: [{ name: 'category', value: 'default { null; }', line: 5 }] },
  ] },
  { path: '/etc/bind/pelagos/keys.conf', managed: true, statements: [
    { name: 'key', value: '"ddi-admin"', line: 2, children: [{ name: 'algorithm', value: 'hmac-sha256', line: 3 }] },
    { name: 'dnssec-policy', value: '"fast"', line: 5, children: [{ name: 'signatures-validity', value: '14d', line: 6 }] },
  ] },
  { path: '/etc/bind/pelagos/pelagos.conf', managed: true, statements: [{ name: 'include', value: '"/etc/bind/pelagos/keys.conf"', line: 2 }] },
  { path: '/etc/bind/pelagos/options.conf', managed: true, statements: [] },
  { path: '/etc/bind/pelagos/views/inside.conf', managed: true, statements: [] },
]

describe('what the BIND editor may change', () => {
  it('keeps user files to their options block', () => {
    const [user] = files()
    expect(editableAt(user, [0, 0], true)).toBe(true)
    expect(editableAt(user, [0], true)).toBe(false)
    expect(editableAt(user, [1, 0], true)).toBe(false)
    expect(canAddTop(user, true)).toBe(false)
    expect(canAddInside(user, [0], true)).toBe(true)
    expect(canAddInside(user, [1], true)).toBe(false)
  })
  it('opens managed files except dedicated statements and pelagos.conf', () => {
    const [, keys, pelagos, options, view] = files()
    expect(editableAt(keys, [0], true)).toBe(false)
    expect(editableAt(keys, [1], true)).toBe(true)
    expect(editableAt(keys, [1, 0], true)).toBe(true)
    expect(editableAt(keys, [1], false)).toBe(false)
    expect(canAddTop(keys, true) && canAddTop(options, true)).toBe(true)
    expect(canAddTop(pelagos, true) || editableAt(pelagos, [0], true)).toBe(false)
    expect(topContext(options)).toBe('options')
    expect(topContext(view)).toBe('view')
    expect(topContext(keys)).toBe(null)
  })
  it('targets the managed file with raw changes', () => {
    const original = files()
    let edited = addStatement(original, [3], { name: 'logging', value: null, children: [{ name: 'category', value: 'lame-servers { null; }' }] })
    edited = removeStatement(edited, [1, 1])
    const changes = buildChanges(original, edited)
    expect(changes).toEqual([
      expect.objectContaining({ op: 'delete', target: 'raw:/etc/bind/pelagos/keys.conf', after: null }),
      expect.objectContaining({ op: 'add', target: 'raw:/etc/bind/pelagos/options.conf', before: null }),
    ])
    expect(changes[1].after).toContain('logging {')
  })
})
