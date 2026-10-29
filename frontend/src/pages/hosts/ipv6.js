// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 (architecture section 27): the server filters, the class badges and the
// exception targets of a row (ipv6_missing_aaaa and ipv6_stale_aaaa keys).

export const IPV6_TAB = 'ipv6'
export const FILTERS = ['missing_aaaa', 'missing_ptr', 'stale', 'unknown', 'random_mac']
export const CLASSES = ['eui64', 'stable', 'temporary', 'unknown']
export const CLASS_VARIANT = { eui64: 'teal', stable: 'success', temporary: 'gray', unknown: 'warning' }
const PROPOSABLE = new Set(['eui64', 'stable'])

export const validFilter = (value) => (FILTERS.includes(value) ? value : '')

// The hosts page link of an IPv6 view, as the alert links and the URL state use it.
export function ipv6Path({ filter, zone } = {}) {
  const q = new URLSearchParams({ tab: IPV6_TAB })
  if (filter) q.set('filter', filter)
  if (zone) q.set('zone', zone)
  return `/hosts?${q.toString()}`
}

// AAAA records of the row whose address no source observes (the stale candidates).
export function unobservedAaaa(row) {
  const seen = new Set((row.observed || []).map((o) => o.address))
  return (row.aaaa || []).filter((a) => !seen.has(a))
}

// What an admin may except on a row: the whole host or one address, for the missing AAAA
// check, and the unobserved AAAA for the stale check. Keys use the API's normalized MAC and address.
export function exceptionTargets(row) {
  const out = []
  const aaaa = new Set(row.aaaa || [])
  const missing = (row.observed || []).filter((o) => PROPOSABLE.has(o.class) && !aaaa.has(o.address))
  if (row.mac && !row.excepted && (missing.length || row.proposal)) {
    out.push({ kind: 'ipv6_missing_aaaa', key: `mac:${row.mac}`, scope: 'host' })
  }
  for (const o of missing) out.push({ kind: 'ipv6_missing_aaaa', key: `addr:${o.address}`, scope: 'address', address: o.address })
  const stale = unobservedAaaa(row)
  if (stale.length && row.mac) out.push({ kind: 'ipv6_stale_aaaa', key: `mac:${row.mac}`, scope: 'host' })
  for (const a of stale) out.push({ kind: 'ipv6_stale_aaaa', key: `addr:${a}`, scope: 'address', address: a })
  return out
}

// "ns2 (neighbors): timed out" lines of meta.unavailable.
export function unavailableLines(unavailable = [], nameOf = (id) => id) {
  return unavailable.map((u) => `${nameOf(u.node_id)} (${u.source}${u.error ? `: ${u.error}` : ''})`)
}
