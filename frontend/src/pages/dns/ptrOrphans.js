// SPDX-License-Identifier: Apache-2.0
// Pure helpers of the orphan PTR page: row identity, category filter and plan bodies.

export const CATEGORIES = ['orphan', 'external', 'excepted', 'all']

export const orphanKey = (row) => `${row.view}|${row.zone}|${row.name}|${row.target}`

// Ignored rows show only under "excepted" (and "all"), whatever their category.
export function filterOrphans(rows, category) {
  if (category === 'all' || !category) return rows
  if (category === 'excepted') return rows.filter((r) => r.excepted)
  return rows.filter((r) => !r.excepted && r.category === category)
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
