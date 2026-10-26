// SPDX-License-Identifier: Apache-2.0
// Settings and modules forms: partial PUT bodies and number parsing (the settings
// screen itself is built from the server's schema, see settingsSchema.js).

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)

// Partial object holding only what changed from `before` to `after`; null when equal.
export function diffPatch(before, after) {
  if (!isObject(before) || !isObject(after)) return JSON.stringify(before) === JSON.stringify(after) ? null : after
  const out = {}
  for (const key of Object.keys(after)) {
    const sub = diffPatch(before[key], after[key])
    if (sub !== null) out[key] = isObject(after[key]) && isObject(before[key]) ? sub : after[key]
  }
  return Object.keys(out).length ? out : null
}

export const modulesPatch = diffPatch

// Set a cluster module; turning dhcpv6 off also stops kea6 on every node.
export function setClusterModule(modules, key, value) {
  const next = { ...modules, cluster: { ...modules.cluster, [key]: value } }
  if (key === 'dhcpv6' && !value && isObject(modules.nodes)) {
    next.nodes = Object.fromEntries(Object.entries(modules.nodes).map(([id, mods]) => [id, mods?.kea6 ? { ...mods, kea6: false } : mods]))
  }
  return next
}

export function getIn(obj, path) {
  return path.reduce((acc, k) => (acc == null ? undefined : acc[k]), obj)
}

export function setIn(obj, path, value) {
  if (!path.length) return value
  const [head, ...rest] = path
  return { ...(obj || {}), [head]: setIn(obj?.[head], rest, value) }
}

// Parse a text input for a numeric field; null when invalid.
export function parseNumber(type, text) {
  const raw = String(text).trim()
  if (type === 'integer') return /^-?\d+$/.test(raw) ? Number(raw) : null
  return /^-?\d+(\.\d+)?$/.test(raw) ? Number(raw) : null
}
