// SPDX-License-Identifier: Apache-2.0
// Counters of a BIND instance (BindInstanceStats, read from the statistics channel)
// reduced to what the instances screen shows, and their number formatting.

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0)

export function formatCount(value, language) {
  if (value === null || value === undefined) return '-'
  return new Intl.NumberFormat(language).format(num(value))
}

const BYTE_UNITS = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte']

// Binary multiples shown with the SI unit names Intl knows (kB, MB, GB).
export function formatBytes(value, language) {
  if (value === null || value === undefined) return '-'
  let n = num(value)
  let i = 0
  while (n >= 1024 && i < BYTE_UNITS.length - 1) {
    n /= 1024
    i += 1
  }
  return new Intl.NumberFormat(language, { style: 'unit', unit: BYTE_UNITS[i], unitDisplay: 'short', maximumFractionDigits: 1 }).format(n)
}

export function formatPercent(ratio, language) {
  return new Intl.NumberFormat(language, { style: 'percent', maximumFractionDigits: 1 }).format(num(ratio))
}

// Headline counters; a counter BIND did not report reads as 0.
export function headlineCounters(stats) {
  const ns = stats?.nsstats || {}
  const zs = stats?.zonestats || {}
  const rs = stats?.resstats || {}
  const opQueries = num(stats?.opcodes?.QUERY)
  return {
    queries: num(ns.Requestv4) + num(ns.Requestv6) || opQueries,
    responses: num(ns.Response),
    recursive: num(ns.QryRecursion),
    updates: num(ns.UpdateDone),
    updateFailures: num(ns.UpdateFail),
    transfers: num(zs.XfrSuccess),
    validated: num(rs.ValOk) + num(rs.ValNegOk),
    validationFailures: num(rs.ValFail),
  }
}

// The largest non-zero counters of a group, with their share of the group's total.
export function topCounters(group, limit = 8) {
  const entries = Object.entries(group || {}).map(([name, v]) => [name, num(v)]).filter(([, v]) => v > 0)
  const total = entries.reduce((sum, [, v]) => sum + v, 0)
  return entries
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name, value]) => ({ name, value, share: total ? value / total : 0 }))
}

// Seconds since the instance booted, or null when unknown.
export function uptimeSeconds(stats, now = Date.now()) {
  const boot = stats?.boot_time ? new Date(stats.boot_time).getTime() : NaN
  return Number.isNaN(boot) ? null : Math.max(0, Math.round((now - boot) / 1000))
}
