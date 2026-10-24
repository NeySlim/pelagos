// SPDX-License-Identifier: Apache-2.0
// Immutable path edits on the Kea configuration JSON for the advanced editor.
// Paths are arrays of keys (strings for objects, numbers for arrays); JsonTree
// reports them dot-joined, which is safe because Kea keys never contain dots.

export const parsePath = (text) => (text ? String(text).split('.').map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [])

export function getPath(obj, path) {
  return path.reduce((acc, key) => (acc == null ? undefined : acc[key]), obj)
}

function shallowCopy(value) {
  return Array.isArray(value) ? [...value] : { ...value }
}

export function setPath(obj, path, value) {
  if (!path.length) return value
  const [head, ...rest] = path
  const copy = shallowCopy(obj ?? (typeof head === 'number' ? [] : {}))
  copy[head] = setPath(copy[head], rest, value)
  return copy
}

export function deletePath(obj, path) {
  if (!path.length) return obj
  const [head, ...rest] = path
  const copy = shallowCopy(obj)
  if (rest.length) copy[head] = deletePath(copy[head], rest)
  else if (Array.isArray(copy)) copy.splice(head, 1)
  else delete copy[head]
  return copy
}

export function typeOf(value) {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  if (Number.isInteger(value)) return 'integer'
  return typeof value
}

// Starting value for a new key of a schema type.
export function defaultFor(type) {
  return { object: {}, array: [], integer: 0, number: 0, boolean: false, string: '' }[type] ?? null
}

// Parse the text of a scalar editor according to the expected type.
export function parseScalar(type, text) {
  const raw = String(text)
  if (type === 'integer' || type === 'number') {
    if (!/^-?\d+(\.\d+)?$/.test(raw.trim())) return { error: 'number' }
    return { value: Number(raw) }
  }
  if (type === 'boolean') return { value: raw === 'true' }
  if (type === 'null') return { value: null }
  return { value: raw }
}

export function parseJson(text) {
  try {
    return { value: JSON.parse(text) }
  } catch (err) {
    return { error: 'json', detail: err.message }
  }
}

const isObject = (v) => Boolean(v) && typeof v === 'object' && !Array.isArray(v)

// The config may come wrapped in its root key ({Dhcp4: {...}}) or bare: rootPath
// is [root] or [], the path of the object the schema keys describe.
// Accepts `keys` as the documented list of {name, ...} or as a map name -> definition.
export function normalizeSchema(schema) {
  if (!schema || Array.isArray(schema.keys)) return schema
  const keys = Object.entries(schema.keys || {}).map(([name, def]) => ({ name, ...(def || {}) }))
  return { ...schema, keys }
}

export function schemaRoot(config, schema) {
  const root = schema?.root
  if (root && isObject(config) && root in config) return { body: config[root], rootPath: [root] }
  return { body: config, rootPath: [] }
}

// Check a draft against the top-level schema keys: types of known keys only.
export function checkSchema(config, schema) {
  const root = schema?.root
  if (!root) return []
  const { body, rootPath } = schemaRoot(config, schema)
  if (!isObject(body)) return [{ path: root, problem: 'missingRoot' }]
  const at = (name) => [...rootPath, name].join('.')
  const problems = []
  for (const key of schema.keys || []) {
    if (!(key.name in body)) continue
    const actual = typeOf(body[key.name])
    const expected = key.type
    const ok = expected === actual || (expected === 'number' && actual === 'integer')
    if (!ok) problems.push({ path: at(key.name), problem: 'type', expected, actual })
    else if (key.minimum !== undefined && typeof body[key.name] === 'number' && body[key.name] < key.minimum) {
      problems.push({ path: at(key.name), problem: 'minimum', expected: key.minimum, actual: body[key.name] })
    }
  }
  return problems
}

// Schema entry describing the key at `path`, when it is a direct child of the root.
export function schemaKeyAt(config, schema, path) {
  if (!schema) return null
  const { rootPath } = schemaRoot(config, schema)
  if (path.length !== rootPath.length + 1 || rootPath.some((k, i) => path[i] !== k)) return null
  return schema.keys?.find((k) => k.name === path[path.length - 1]) || null
}

// True when `path` designates the object the schema keys describe.
export function isSchemaRoot(config, schema, path) {
  if (!schema) return false
  const { rootPath } = schemaRoot(config, schema)
  return path.length === rootPath.length && rootPath.every((k, i) => path[i] === k)
}
