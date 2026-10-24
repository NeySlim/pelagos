// SPDX-License-Identifier: Apache-2.0
// Kea statistic-get-all output split into server-wide counters and per-subnet counters.
// Each Kea value is a list of [value, timestamp] samples, newest first.

export function latestValue(samples) {
  if (Array.isArray(samples)) {
    const first = samples[0]
    return Array.isArray(first) ? first[0] : first ?? null
  }
  return samples ?? null
}

const SUBNET_RE = /^subnet\[(\d+)\]\.(?:pool\[(\d+)\]\.|pd-pool\[(\d+)\]\.)?(.+)$/

// Server-wide counters sorted by name, and one row per subnet: a subnet-level counter wins,
// else the sum of its pools' counters of that name.
export function splitStatistics(statistics) {
  const global = []
  const subnets = new Map()
  for (const [key, samples] of Object.entries(statistics || {})) {
    const value = latestValue(samples)
    const m = key.match(SUBNET_RE)
    if (!m) {
      global.push({ name: key, value })
      continue
    }
    const id = Number(m[1])
    const pooled = m[2] !== undefined || m[3] !== undefined
    const row = subnets.get(id) || { id, own: {}, pools: {} }
    const bucket = pooled ? row.pools : row.own
    if (typeof value === 'number') bucket[m[4]] = (bucket[m[4]] || 0) + value
    subnets.set(id, row)
  }
  const rows = [...subnets.values()]
    .sort((a, b) => a.id - b.id)
    .map(({ id, own, pools }) => ({ id, counters: { ...pools, ...own } }))
  global.sort((a, b) => a.name.localeCompare(b.name))
  return { global, subnets: rows }
}

// Address counters shown as subnet columns, in this order, when any subnet reports them.
const SUBNET_COLUMNS = [
  'total-addresses', 'assigned-addresses', 'declined-addresses', 'reclaimed-leases',
  'total-nas', 'assigned-nas', 'total-pds', 'assigned-pds',
]

export function subnetColumns(rows) {
  const seen = new Set(rows.flatMap((r) => Object.keys(r.counters)))
  return SUBNET_COLUMNS.filter((c) => seen.has(c))
}

// Address use of a subnet row in percent: addresses (v4, v6 NA) or delegated prefixes.
export function subnetUtilization(row) {
  const c = row?.counters || {}
  for (const [assigned, total] of [['assigned-addresses', 'total-addresses'], ['assigned-nas', 'total-nas'], ['assigned-pds', 'total-pds']]) {
    if (typeof c[total] === 'number' && c[total] > 0 && typeof c[assigned] === 'number') {
      return { assigned: c[assigned], total: c[total], percent: (c[assigned] / c[total]) * 100 }
    }
  }
  return null
}

// GET /series/pools summed over the pools: one { t, value } point per timestamp with
// the percentage of all addresses in use, oldest first.
export function poolHistory(series) {
  const byTime = new Map()
  for (const s of series || []) {
    for (const [ts, assigned, total] of s.points || []) {
      const t = Date.parse(ts)
      if (!Number.isFinite(t)) continue
      const cur = byTime.get(t) || { assigned: 0, total: 0 }
      cur.assigned += Number(assigned) || 0
      cur.total += Number(total) || 0
      byTime.set(t, cur)
    }
  }
  return [...byTime.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([t, { assigned, total }]) => ({ t, value: total > 0 ? (assigned / total) * 100 : 0 }))
}
