// SPDX-License-Identifier: Apache-2.0
// Pure helpers of the orphan PTR page: row identity, category filter and plan bodies.

export const CATEGORIES = ['orphan', 'external', 'excepted', 'all']
// Who set the PTR: the DHCP server through DDNS (a DHCID record sits beside it) or anyone else.
export const ORIGINS = ['all', 'ddns', 'manual']

export const orphanKey = (row) => `${row.view}|${row.zone}|${row.name}|${row.target}`

// Ignored rows show only under "excepted" (and "all"), whatever their category.
export function filterOrphans(rows, category, origin = 'all') {
  const byOrigin = origin === 'ddns' ? rows.filter((r) => r.ddns) : origin === 'manual' ? rows.filter((r) => !r.ddns) : rows
  if (category === 'all' || !category) return byOrigin
  if (category === 'excepted') return byOrigin.filter((r) => r.excepted)
  return byOrigin.filter((r) => !r.excepted && r.category === category)
}

const viewOf = (row) => (row.view && row.view !== '_default' ? { view: row.view } : {})

// POST /dns/ptr/orphans/plan: remove each row's target from its PTR RRset.
export function deleteBody(rows) {
  return { delete: rows.map((r) => ({ zone: r.zone, name: r.name, target: r.target, ...viewOf(r) })) }
}

// POST /dns/ptr/orphans/plan: add each row's address to its target's A/AAAA.
export function createBody(rows) {
  return { create: rows.map((r) => ({ ip: r.ip, target: r.target, ...viewOf(r) })) }
}

// Exceptions of rows a plan settles: once it applies, the PTR they covered is gone or matches.
export function settledExceptions(rows) {
  return [...new Set(rows.filter((r) => r.exception?.id).map((r) => r.exception.id))]
}
