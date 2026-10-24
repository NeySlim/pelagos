// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { argKind, toForm, fromForm, validateForm, parseList, serialize, fileText, buildChanges, replaceStatement, removeStatement, addStatement, getAt, statementsFor } from './bindGrammar'
import { unifiedDiff, diffLines } from './lineDiff'
import { parsePath, getPath, setPath, deletePath, parseScalar, parseJson, checkSchema, defaultFor, schemaKeyAt, isSchemaRoot } from './keaJson'

const g = (args) => ({ name: 'x', args })

describe('BIND grammar kinds', () => {
  it('classifies argument grammars', () => {
    expect(argKind('boolean').kind).toBe('boolean')
    expect(argKind('integer').kind).toBe('integer')
    expect(argKind('quoted_string').kind).toBe('quoted')
    expect(argKind('string').kind).toBe('string')
    expect(argKind('block').kind).toBe('block')
    expect(argKind('( first | only )')).toEqual({ kind: 'enum', values: ['first', 'only'] })
    expect(argKind('( explicit | primary-only | boolean )').values).toEqual(['explicit', 'primary-only', 'yes', 'no'])
    expect(argKind('address_match_list').kind).toBe('list')
    expect(argKind('[ port integer ] { ( ipv4_address | ipv6_address ) [ port integer ]; ... }').kind).toBe('list')
    expect(argKind('string { algorithm string; secret string; }').kind).toBe('raw')
  })

  it('round-trips values through the form', () => {
    expect(fromForm(toForm(g('quoted_string'), '"/var/cache/bind"'))).toBe('"/var/cache/bind"')
    const list = toForm(g('address_match_list'), '{ localhost; 192.0.2.0/24; }')
    expect(list.items).toEqual(['localhost', '192.0.2.0/24'])
    expect(fromForm({ ...list, items: [...list.items, 'key ddi-read'] })).toBe('{ localhost; 192.0.2.0/24; key ddi-read; }')
    expect(fromForm({ ...list, items: [] })).toBe('{ }')
    expect(fromForm(toForm(g('[ port integer ] { x; ... }'), 'port 5353 { 192.0.2.1; }'))).toBe('port 5353 { 192.0.2.1; }')
    expect(fromForm(toForm(g('( first | only )'), 'only'))).toBe('only')
    // A value the grammar cannot type falls back to raw text.
    expect(toForm(g('( first | only )'), 'sometimes').kind).toBe('raw')
    expect(toForm(g('address_match_list'), '{ !{ 192.0.2.1; }; any; }').kind).toBe('raw')
    expect(fromForm({ kind: 'quoted', value: 'a"b' })).toBe('"a\\"b"')
    const escaped = '"a\\"b\\\\c"'
    expect(toForm(g('quoted_string'), escaped).value).toBe('a"b\\c')
    expect(fromForm(toForm(g('quoted_string'), fromForm(toForm(g('quoted_string'), escaped))))).toBe(escaped)
  })

  it('parses lists and validates forms', () => {
    expect(parseList('{ a; b; }')).toEqual({ prefix: '', items: ['a', 'b'] })
    expect(parseList('none')).toEqual({ prefix: '', items: ['none'] })
    expect(validateForm({ kind: 'integer', value: '30m' })).toBe(null)
    expect(validateForm({ kind: 'integer', value: 'ten' })).toBe('integer')
    expect(validateForm({ kind: 'enum', value: '' })).toBe('required')
    expect(validateForm({ kind: 'raw', value: 'yes;' })).toBe('semicolon')
  })

  it('lists statements allowed in a context', () => {
    const grammar = { statements: [{ name: 'recursion', contexts: ['options', 'view'] }, { name: 'file', contexts: ['zone'] }] }
    expect(statementsFor(grammar, 'options').map((s) => s.name)).toEqual(['recursion'])
    expect(statementsFor(grammar, 'zone').map((s) => s.name)).toEqual(['file'])
  })
})

const files = () => [
  {
    path: '/etc/bind/named.conf.options',
    managed: false,
    statements: [
      { name: 'options', value: null, line: 1, children: [
        { name: 'directory', value: '"/var/cache/bind"', line: 2 },
        { name: 'recursion', value: 'yes', line: 3 },
      ] },
    ],
  },
  {
    path: '/etc/bind/named.conf.local',
    managed: false,
    statements: [{ name: 'zone', value: '"example.lan"', line: 1, children: [{ name: 'type', value: 'primary', line: 2 }] }],
  },
]

describe('statement trees', () => {
  it('serializes in named-checkconf -p style', () => {
    expect(fileText(files()[0])).toBe('options {\n\tdirectory "/var/cache/bind";\n\trecursion yes;\n};\n')
    expect(serialize([{ name: 'zone', value: '"a"', children: [] }])).toBe('zone "a" {\n};')
  })

  it('edits by path without touching the original', () => {
    const original = files()
    const edited = replaceStatement(original, [0, 0, 1], { value: 'no' })
    expect(getAt(edited[0].statements, [0, 1]).value).toBe('no')
    expect(getAt(original[0].statements, [0, 1]).value).toBe('yes')
    expect(removeStatement(original, [0, 0, 0])[0].statements[0].children.map((s) => s.name)).toEqual(['recursion'])
    expect(addStatement(original, [1], { name: 'acl', value: '"lan"', line: null, children: [] })[1].statements).toHaveLength(2)
    expect(addStatement(original, [0, 0], { name: 'forward', value: 'only', line: null })[0].statements[0].children).toHaveLength(3)
  })

  it('turns option edits into options/<statement> changes', () => {
    const original = files()
    let edited = replaceStatement(original, [0, 0, 1], { value: 'no' })
    edited = addStatement(edited, [0, 0], { name: 'forward', value: 'only', line: null })
    edited = removeStatement(edited, [0, 0, 0])
    const changes = buildChanges(original, edited)
    expect(changes).toEqual([
      { op: 'delete', target: 'options/directory', before: '"/var/cache/bind"', after: null, node_ids: [] },
      { op: 'replace', target: 'options/recursion', before: 'yes', after: 'no', node_ids: [] },
      { op: 'add', target: 'options/forward', before: null, after: 'only', node_ids: [] },
    ])
  })

  it('turns any other edit into per-statement raw:<file> changes', () => {
    const original = files()
    const edited = replaceStatement(original, [1, 0, 0], { value: 'secondary' })
    expect(buildChanges(original, edited)).toEqual([
      {
        op: 'replace',
        target: 'raw:/etc/bind/named.conf.local',
        before: 'zone "example.lan" {\n\ttype primary;\n};',
        after: 'zone "example.lan" {\n\ttype secondary;\n};',
        node_ids: [],
      },
    ])
    expect(buildChanges(original, files())).toEqual([])
  })

  it('emits add and delete raw changes for top-level statements only', () => {
    const original = files()
    let edited = addStatement(original, [1], { name: 'acl', value: '"lan"', line: null, children: [{ name: '192.0.2.0/24', value: null, line: null }] })
    edited = removeStatement(edited, [1, 0])
    expect(buildChanges(original, edited)).toEqual([
      { op: 'delete', target: 'raw:/etc/bind/named.conf.local', before: 'zone "example.lan" {\n\ttype primary;\n};', after: null, node_ids: [] },
      { op: 'add', target: 'raw:/etc/bind/named.conf.local', before: null, after: 'acl "lan" {\n\t192.0.2.0/24;\n};', node_ids: [] },
    ])
  })
})

describe('line diff', () => {
  it('is empty for equal texts', () => {
    expect(unifiedDiff('a\nb', 'a\nb')).toBe('')
  })

  it('produces hunks with context', () => {
    const before = Array.from({ length: 20 }, (_, i) => `line ${i}`).join('\n')
    const after = before.replace('line 2', 'line two').replace('line 17', 'line seventeen')
    const diff = unifiedDiff(before, after, 'f.conf')
    expect(diff.startsWith('--- a/f.conf\n+++ b/f.conf\n')).toBe(true)
    expect(diff.match(/^@@/gm)).toHaveLength(2)
    expect(diff).toContain('@@ -1,6 +1,6 @@')
    expect(diff).toContain('-line 2\n+line two')
    expect(diff).not.toContain(' line 9')
  })

  it('handles additions to an empty text', () => {
    expect(unifiedDiff('', 'x\ny', 'new')).toBe('--- a/new\n+++ b/new\n@@ -0,0 +1,2 @@\n+x\n+y\n')
    expect(diffLines('a', '').map((o) => o.kind)).toEqual(['-'])
  })

  it('stays fast on large texts with one changed line', () => {
    const before = Array.from({ length: 5000 }, (_, i) => `"line-${i}": ${i},`).join('\n')
    const after = before.replace('"line-2500": 2500,', '"line-2500": 42,')
    const started = Date.now()
    const diff = unifiedDiff(before, after, 'big.json')
    expect(Date.now() - started).toBeLessThan(1000)
    expect(diff).toBe('--- a/big.json\n+++ b/big.json\n@@ -2498,7 +2498,7 @@\n "line-2497": 2497,\n "line-2498": 2498,\n "line-2499": 2499,\n-"line-2500": 2500,\n+"line-2500": 42,\n "line-2501": 2501,\n "line-2502": 2502,\n "line-2503": 2503,\n')
  })

  it('falls back to removed then added above the LCS budget', () => {
    const before = Array.from({ length: 2500 }, (_, i) => `a${i}`).join('\n')
    const after = Array.from({ length: 2500 }, (_, i) => `b${i}`).join('\n')
    const ops = diffLines(before, after)
    expect(ops).toHaveLength(5000)
    expect(ops.slice(0, 2500).every((o) => o.kind === '-')).toBe(true)
    expect(ops.slice(2500).every((o) => o.kind === '+')).toBe(true)
  })
})

describe('Kea JSON paths', () => {
  const config = { Dhcp4: { 'valid-lifetime': 3600, subnet4: [{ id: 1, subnet: '192.0.2.0/24' }] } }

  it('reads and writes by path immutably', () => {
    expect(parsePath('Dhcp4.subnet4.0.id')).toEqual(['Dhcp4', 'subnet4', 0, 'id'])
    expect(parsePath('')).toEqual([])
    expect(getPath(config, ['Dhcp4', 'subnet4', 0, 'subnet'])).toBe('192.0.2.0/24')
    const next = setPath(config, ['Dhcp4', 'subnet4', 0, 'id'], 7)
    expect(next.Dhcp4.subnet4[0].id).toBe(7)
    expect(config.Dhcp4.subnet4[0].id).toBe(1)
    expect(Array.isArray(next.Dhcp4.subnet4)).toBe(true)
    expect(deletePath(config, ['Dhcp4', 'valid-lifetime']).Dhcp4).not.toHaveProperty('valid-lifetime')
    expect(deletePath(config, ['Dhcp4', 'subnet4', 0]).Dhcp4.subnet4).toEqual([])
  })

  it('parses scalars and JSON', () => {
    expect(parseScalar('integer', '42')).toEqual({ value: 42 })
    expect(parseScalar('integer', 'x').error).toBe('number')
    expect(parseScalar('boolean', 'false')).toEqual({ value: false })
    expect(parseScalar('string', ' a ')).toEqual({ value: ' a ' })
    expect(parseJson('{"a":1}')).toEqual({ value: { a: 1 } })
    expect(parseJson('{').error).toBe('json')
    expect(defaultFor('array')).toEqual([])
  })

  it('checks top-level types against the schema', () => {
    const schema = { root: 'Dhcp4', keys: [{ name: 'valid-lifetime', type: 'integer', minimum: 0 }, { name: 'subnet4', type: 'array' }] }
    expect(checkSchema(config, schema)).toEqual([])
    expect(checkSchema({ Dhcp4: { 'valid-lifetime': '1h' } }, schema)).toEqual([{ path: 'Dhcp4.valid-lifetime', problem: 'type', expected: 'integer', actual: 'string' }])
    expect(checkSchema({ Dhcp4: { 'valid-lifetime': -1 } }, schema)[0].problem).toBe('minimum')
    expect(checkSchema([], schema)).toEqual([{ path: 'Dhcp4', problem: 'missingRoot' }])
    expect(checkSchema(config, null)).toEqual([])
  })

  it('accepts a bare config object as well as a wrapped one', () => {
    const schema = { root: 'Dhcp4', keys: [{ name: 'valid-lifetime', type: 'integer' }, { name: 'subnet4', type: 'array' }] }
    const bare = config.Dhcp4
    expect(checkSchema(bare, schema)).toEqual([])
    expect(checkSchema({ 'valid-lifetime': 'x' }, schema)).toEqual([{ path: 'valid-lifetime', problem: 'type', expected: 'integer', actual: 'string' }])
    expect(schemaKeyAt(bare, schema, ['subnet4']).type).toBe('array')
    expect(schemaKeyAt(config, schema, ['Dhcp4', 'subnet4']).type).toBe('array')
    expect(schemaKeyAt(config, schema, ['subnet4'])).toBe(null)
    expect(isSchemaRoot(bare, schema, [])).toBe(true)
    expect(isSchemaRoot(config, schema, ['Dhcp4'])).toBe(true)
    expect(isSchemaRoot(config, schema, [])).toBe(false)
  })
})
