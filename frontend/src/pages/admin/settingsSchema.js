// SPDX-License-Identifier: Apache-2.0
// Settings schema (GET /admin/settings/schema, backend core/settings_registry.py): sections,
// validation of a draft, former names. Pure functions shared by the settings screen and the mock.

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

export function getPath(obj, key) {
  return String(key).split('.').reduce((acc, k) => (acc == null ? undefined : acc[k]), obj)
}

export function setPath(obj, key, value) {
  const [head, ...rest] = String(key).split('.')
  if (!rest.length) return { ...(obj || {}), [head]: value }
  return { ...(obj || {}), [head]: setPath(obj?.[head], rest.join('.'), value) }
}

// Domains in schema order, each with its groups (null first) in order of appearance.
export function sectionsOf(schema) {
  const sections = new Map((schema?.domains || []).map((d) => [d, new Map()]))
  for (const spec of schema?.settings || []) {
    const domain = spec.key.split('.')[0]
    if (!sections.has(domain)) sections.set(domain, new Map())
    const groups = sections.get(domain)
    const group = spec.group || null
    if (!groups.has(group)) groups.set(group, [])
    groups.get(group).push(spec)
  }
  return [...sections.entries()]
    .filter(([, groups]) => groups.size)
    .map(([id, groups]) => ({ id, groups: [...groups.entries()].map(([gid, fields]) => ({ id: gid, fields })) }))
}

// Defaults as a nested [settings] table.
export function defaultsOf(schema) {
  let out = {}
  for (const spec of schema?.settings || []) out = setPath(out, spec.key, structuredClone(spec.default))
  return out
}

const isNumber = (v) => typeof v === 'number' && Number.isFinite(v)
const NAME_RE = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,62}$/
const matchesPattern = (pattern, value) => !pattern || new RegExp(pattern).test(value)

// {code, params} describing why `value` does not fit `spec`; null when it does.
export function fieldError(spec, value) {
  switch (spec.type) {
    case 'boolean':
      return typeof value === 'boolean' ? null : { code: 'boolean' }
    case 'integer':
    case 'number':
      if (!isNumber(value)) return { code: 'number' }
      if (spec.type === 'integer' && !Number.isInteger(value)) return { code: 'integer' }
      if ((spec.min != null && value < spec.min) || (spec.max != null && value > spec.max)) return { code: 'range', params: { min: spec.min, max: spec.max } }
      return null
    case 'string':
      if (typeof value !== 'string' || !value.trim()) return { code: 'required' }
      if (matchesPattern(spec.pattern, value)) return null
      return { code: spec.key.endsWith('_time') ? 'time' : 'name' }
    case 'url':
      if (typeof value !== 'string') return { code: 'required' }
      return !value || /^https:\/\/[^\s/]+(\/\S*)?$/.test(value) ? null : { code: 'https' }
    case 'list': {
      if (!Array.isArray(value) || !value.every((v) => typeof v === 'string')) return { code: 'list' }
      const bad = value.find((v) => !matchesPattern(spec.pattern, v))
      return bad === undefined ? null : { code: 'item', params: { item: bad } }
    }
    case 'map':
      return viewKeysError(value)
    default:
      return null
  }
}

// dns.view_keys: view -> key name, or {admin, read} key names.
export function viewKeysError(value) {
  if (!isObject(value)) return { code: 'object' }
  for (const [view, entry] of Object.entries(value)) {
    if (!NAME_RE.test(view) || view === '_default') return { code: 'viewName', params: { view } }
    let names = null
    if (typeof entry === 'string') names = [entry]
    else if (isObject(entry) && entry.admin && Object.keys(entry).every((k) => k === 'admin' || k === 'read')) names = Object.values(entry)
    if (!names || !names.every((n) => typeof n === 'string' && NAME_RE.test(n))) return { code: 'viewKey', params: { view } }
  }
  return null
}

// View key rows for the editor and back: [{view, admin, read}].
export function viewKeyRows(map) {
  return Object.entries(map || {}).map(([view, entry]) => (typeof entry === 'string' ? { view, admin: entry, read: '' } : { view, admin: entry?.admin || '', read: entry?.read || '' }))
}

export function rowsToViewKeys(rows) {
  const out = {}
  for (const { view, admin, read } of rows) {
    const name = view.trim()
    if (!name) continue
    out[name] = read.trim() ? { admin: admin.trim(), read: read.trim() } : admin.trim()
  }
  return out
}

// {key: {code, params}} for every field of `settings` that breaks its rule or a pair.
export function validateSettings(schema, settings) {
  const errors = {}
  for (const spec of schema?.settings || []) {
    const value = getPath(settings, spec.key)
    if (value === undefined) continue
    const err = fieldError(spec, value)
    if (err) errors[spec.key] = err
  }
  for (const { lower, higher, strict } of schema?.pairs || []) {
    if (errors[lower] || errors[higher]) continue
    const a = getPath(settings, lower)
    const b = getPath(settings, higher)
    if (!isNumber(a) || !isNumber(b)) continue
    if (a > b || (strict && a === b)) errors[lower] = { code: strict ? 'lower' : 'atMost', params: { other: higher } }
  }
  return errors
}

// A body with former names (schema.renamed) moved to the current ones; the current name wins.
export function translateLegacy(schema, body) {
  let out = structuredClone(body || {})
  for (const [old, current] of Object.entries(schema?.renamed || {})) {
    const value = getPath(out, old)
    if (value === undefined || isObject(value)) continue
    out = removePath(out, old)
    const factor = schema.scaled?.[old]
    if (getPath(out, current) === undefined) out = setPath(out, current, factor && isNumber(value) ? Math.round(value * factor * 1e6) / 1e6 : value)
  }
  return out
}

function removePath(obj, key) {
  const [head, ...rest] = key.split('.')
  if (!isObject(obj) || !(head in obj)) return obj
  const out = { ...obj }
  if (!rest.length) delete out[head]
  else {
    out[head] = removePath(out[head], rest.join('.'))
    if (isObject(out[head]) && !Object.keys(out[head]).length) delete out[head]
  }
  return out
}

// Keys of a PUT body that the schema does not know (managed tables and typos alike).
export function unknownKeys(schema, body) {
  const known = new Set((schema?.settings || []).map((s) => s.key))
  const prefixes = new Set([...known].flatMap((k) => k.split('.').slice(0, -1).map((_, i, parts) => parts.slice(0, i + 1).join('.'))))
  const out = []
  const walk = (node, path) => {
    for (const [k, v] of Object.entries(node)) {
      const key = path ? `${path}.${k}` : k
      if (known.has(key)) continue
      if (isObject(v) && prefixes.has(key)) walk(v, key)
      else out.push(key)
    }
  }
  walk(body || {}, '')
  return out
}

// A readable size for a duration setting: [count, unit] in the largest unit that divides it.
export function durationParts(value, unit) {
  const seconds = { seconds: 1, minutes: 60, hours: 3600, days: 86400 }[unit]
  if (!seconds || !isNumber(value) || value <= 0) return null
  const total = value * seconds
  for (const [name, size] of [['days', 86400], ['hours', 3600], ['minutes', 60]]) {
    if (total >= size && size > seconds) return [Math.round((total / size) * 10) / 10, name]
  }
  return null
}

// The query against the key (underscores and dots read as spaces), the label and the help.
export function matchesQuery(spec, texts, query) {
  const q = String(query || '').trim().toLowerCase()
  if (!q) return true
  const hay = [spec.key, spec.key.replace(/[._]/g, ' '), ...[].concat(texts || [])].join('\n').toLowerCase()
  return hay.includes(q)
}
