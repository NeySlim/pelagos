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
