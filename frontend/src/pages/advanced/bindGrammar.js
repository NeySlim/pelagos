// SPDX-License-Identifier: Apache-2.0
// Grammar-driven helpers for the named.conf editor: classify a statement's
// argument grammar (GET /advanced/bind/grammar) into a form kind, convert value
// text to form state and back, serialize statement trees in the canonical style
// of named-checkconf -p, and turn an edited tree into dns.config Changes.

// Form kinds: boolean, enum, integer, quoted, string, list, block, raw.
export function argKind(args) {
  const a = String(args || '').trim()
  if (!a || a === 'block') return { kind: 'block' }
  if (a === 'boolean') return { kind: 'boolean' }
  if (a === 'integer' || a === 'duration' || a === 'percentage' || a === 'size') return { kind: 'integer' }
  if (a === 'quoted_string') return { kind: 'quoted' }
  if (a === 'string') return { kind: 'string' }
  const choice = a.match(/^\(\s*([^()]+?)\s*\)$/)
  if (choice) {
    const values = choice[1].split('|').map((v) => v.trim()).filter(Boolean)
    if (values.every((v) => /^[a-z0-9-]+$/i.test(v))) {
      const expanded = values.flatMap((v) => (v === 'boolean' ? ['yes', 'no'] : [v]))
      return { kind: 'enum', values: [...new Set(expanded)] }
    }
  }
  if (a === 'address_match_list' || /\{[^{}]*;\s*\.\.\.\s*\}/.test(a) || /\{\s*address_match_list\s*\}/.test(a)) return { kind: 'list' }
  return { kind: 'raw' }
}

export function grammarIndex(grammar) {
  const map = new Map()
  for (const s of grammar?.statements || []) map.set(s.name, s)
  return map
}

// Statements of the grammar allowed in a context ("toplevel", "options", "view", "zone").
export function statementsFor(grammar, context) {
  return (grammar?.statements || []).filter((s) => (s.contexts || []).includes(context))
}

// Context of the children of a statement, or of the top level of a file.
export const childContext = (parentName) => parentName || 'toplevel'

// Inverse of the quoting in fromForm(): strip the quotes, then the escapes.
const unquote = (v) => String(v ?? '').replace(/^"(.*)"$/s, '$1').replace(/\\(["\\])/g, '$1')

// Split "[prefix] { a; b; }" into its prefix and top-level elements; null when nested.
export function parseList(value) {
  const text = String(value ?? '').trim()
  const open = text.indexOf('{')
  if (open < 0) return text ? { prefix: '', items: [text] } : { prefix: '', items: [] }
  const close = text.lastIndexOf('}')
  const inner = text.slice(open + 1, close < 0 ? undefined : close)
  if (inner.includes('{')) return null
  return {
    prefix: text.slice(0, open).trim(),
    items: inner.split(';').map((s) => s.trim()).filter(Boolean),
  }
}

export function formatList(prefix, items) {
  const body = items.length ? `{ ${items.join('; ')}; }` : '{ }'
  return prefix ? `${prefix} ${body}` : body
}

// Form state for a value: { kind, value, items?, prefix?, values? }.
export function toForm(statementGrammar, value) {
  const info = argKind(statementGrammar?.args)
  if (info.kind === 'list') {
    const parsed = parseList(value)
    if (parsed) return { ...info, prefix: parsed.prefix, items: parsed.items }
    return { kind: 'raw', value: value ?? '' }
  }
  if (info.kind === 'quoted') return { ...info, value: unquote(value) }
  if (info.kind === 'enum' && value && !info.values.includes(value)) return { kind: 'raw', value }
  if (info.kind === 'boolean' && value && !['yes', 'no', 'true', 'false'].includes(value)) return { kind: 'raw', value }
  return { ...info, value: value ?? '' }
}

export function fromForm(form) {
  switch (form.kind) {
    case 'list':
      return formatList(form.prefix, form.items)
    case 'quoted':
      return `"${String(form.value).replace(/(["\\])/g, '\\$1')}"`
    case 'block':
      return form.value ? form.value : null
    default:
      return String(form.value ?? '').trim()
  }
}

export function validateForm(form) {
  if (form.kind === 'integer' && !/^\d+[a-z%]*$/i.test(String(form.value).trim())) return 'integer'
  if (['boolean', 'enum', 'string', 'raw'].includes(form.kind) && !String(form.value ?? '').trim()) return 'required'
  if (form.kind === 'raw' && /;\s*$/.test(String(form.value).trim()) && !String(form.value).includes('{')) return 'semicolon'
  return null
}

// Canonical text of a statement list (tabs, one statement per line, ';' terminated).
export function serialize(statements, depth = 0) {
  const pad = '\t'.repeat(depth)
  return (statements || [])
    .map((s) => {
      const head = s.value === null || s.value === undefined || s.value === '' ? s.name : `${s.name} ${s.value}`
      if (!s.children) return `${pad}${head};`
      const inner = serialize(s.children, depth + 1)
      return `${pad}${head} {\n${inner}${inner ? '\n' : ''}${pad}};`
    })
    .join('\n')
}

export const fileText = (file) => {
  const body = serialize(file.statements)
  return body ? `${body}\n` : ''
}

// Statement at a path of indices inside a file's statements.
export function getAt(statements, path) {
  let list = statements
  let node = null
  for (const i of path) {
    node = list?.[i]
    list = node?.children
  }
  return node
}

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

// Immutable edits on a files array; `path` is [fileIndex, i0, i1, ...].
export function updateAt(files, path, mutate) {
  const next = clone(files)
  const [fi, ...rest] = path
  if (!rest.length) {
    mutate(next[fi].statements, null)
    return next
  }
  const parentPath = rest.slice(0, -1)
  const parent = parentPath.length ? getAt(next[fi].statements, parentPath) : null
  const list = parent ? parent.children : next[fi].statements
  mutate(list, rest[rest.length - 1])
  return next
}

export const replaceStatement = (files, path, statement) => updateAt(files, path, (list, i) => { list[i] = { ...list[i], ...statement } })
export const removeStatement = (files, path) => updateAt(files, path, (list, i) => { list.splice(i, 1) })

// Append to the block at `path` ([fileIndex] for the top level of the file).
export function addStatement(files, path, statement) {
  const next = clone(files)
  const [fi, ...rest] = path
  if (!rest.length) next[fi].statements.push(statement)
  else {
    const parent = getAt(next[fi].statements, rest)
    parent.children = [...(parent.children || []), statement]
  }
  return next
}

const optionsBlock = (file) => (file.statements || []).filter((s) => s.name === 'options')

// raw:<file> Changes for top-level statements, matched on their provenance line:
// before/after are one canonical statement each (null for add/delete), never the file.
function rawChanges(path, before, after) {
  const target = `raw:${path}`
  const changes = []
  const lines = new Set(before.map((s) => s.line).filter((l) => l != null))
  const byLine = new Map(after.filter((s) => s.line != null && lines.has(s.line)).map((s) => [s.line, s]))
  for (const b of before) {
    const a = b.line != null ? byLine.get(b.line) : undefined
    const bText = serialize([b])
    if (!a) changes.push({ op: 'delete', target, before: bText, after: null, node_ids: [] })
    else if (serialize([a]) !== bText) changes.push({ op: 'replace', target, before: bText, after: serialize([a]), node_ids: [] })
  }
  for (const a of after) {
    if (a.line == null || !lines.has(a.line)) changes.push({ op: 'add', target, before: null, after: serialize([a]), node_ids: [] })
  }
  return changes
}

// dns.config Changes turning `original` files into `edited` ones. A file whose only
// edits are statements directly inside its single options block yields one
// options/<statement> change per statement; any other edit yields one raw:<file>
// change per added, removed or edited top-level statement.
export function buildChanges(original, edited) {
  const changes = []
  edited.forEach((file, idx) => {
    const before = original[idx]
    const beforeText = fileText(before)
    const afterText = fileText(file)
    if (beforeText === afterText) return
    const ob = optionsBlock(before)
    const oa = optionsBlock(file)
    const strip = (f) => fileText({ statements: f.statements.map((s) => (s.name === 'options' ? { ...s, children: [] } : s)) })
    if (ob.length === 1 && oa.length === 1 && strip(before) === strip(file)) {
      const names = new Set([...ob[0].children, ...oa[0].children].map((s) => s.name))
      const counts = (list) => list.reduce((m, s) => m.set(s.name, (m.get(s.name) || 0) + 1), new Map())
      const repeated = [...counts(ob[0].children).values(), ...counts(oa[0].children).values()].some((n) => n > 1)
      if (!repeated) {
        for (const name of names) {
          const b = ob[0].children.find((s) => s.name === name)
          const a = oa[0].children.find((s) => s.name === name)
          const bText = b ? serialize([b]) : null
          const aText = a ? serialize([a]) : null
          if (bText === aText) continue
          const value = (s) => (s.children ? serialize(s.children) : s.value)
          changes.push({
            op: !b ? 'add' : !a ? 'delete' : 'replace',
            target: `options/${name}`,
            before: b ? value(b) : null,
            after: a ? value(a) : null,
            node_ids: [],
          })
        }
        return
      }
    }
    changes.push(...rawChanges(file.path, before.statements || [], file.statements || []))
  })
  return changes
}
