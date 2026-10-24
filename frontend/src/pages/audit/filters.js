// SPDX-License-Identifier: Apache-2.0
// Audit filters: URL search params <-> GET /audit query (architecture section 17).
// `from`/`to` are datetime-local strings in the URL and RFC 3339 UTC in the query.

export const FILTER_KEYS = ['user', 'action', 'target', 'node_id', 'engine', 'result', 'from', 'to']

// Action prefixes the server matches with startsWith (section 11 vocabulary).
export const ACTION_PREFIXES = [
  'dns.', 'dhcp.', 'd2.', 'host.', 'install.', 'import.', 'security.',
  'auth.', 'admin.', 'alert.', 'node.', 'replication.',
]
export const RESULTS = ['ok', 'error', 'rolled_back', 'denied']
export const ENGINES = ['bind', 'kea4', 'kea6', 'd2']

export function filtersFromParams(params) {
  return Object.fromEntries(FILTER_KEYS.map((k) => [k, params.get(k) || '']))
}

export function toRfc3339(local) {
  if (!local) return undefined
  const d = new Date(local)
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString()
}

export function toQuery(filters) {
  const out = {}
  for (const key of FILTER_KEYS) {
    const value = filters[key]
    if (!value) continue
    out[key] = key === 'from' || key === 'to' ? toRfc3339(value) : value
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== undefined))
}
