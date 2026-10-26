// SPDX-License-Identifier: Apache-2.0
// What the tiles derive from GET /dashboard/summary beyond its raw lists.

// DHCP family the HA, DDNS and pool links open: v4 unless no node runs kea-dhcp4
// and one runs kea-dhcp6 (node modules, else the engines of this node that run).
export function dhcpFamily(summary) {
  const modules = (summary?.nodes || []).map((n) => n.peer?.modules || {})
  const engines = summary?.engines || {}
  const has = (engine) => modules.some((m) => m[engine]) || Boolean(engines[engine] && engines[engine].running !== false)
  return !has('kea4') && has('kea6') ? 'v6' : 'v4'
}

// Pool thresholds: GET /dashboard/summary `thresholds` first, then the [settings]
// alert values (admins), then the alert defaults 80 / 95.
export function poolThresholds(summary, settings) {
  const fromSummary = summary?.thresholds || {}
  const pick = (...values) => values.find((v) => typeof v === 'number')
  return {
    warn: pick(fromSummary.pool_warning_percent, settings?.checks?.pool_warning_percent) ?? 80,
    full: pick(fromSummary.pool_critical_percent, settings?.checks?.pool_critical_percent) ?? 95,
  }
}

// Error share of sent updates as a percentage, one decimal, in the UI language's number format.
export function formatErrorRate(errors, sent, language) {
  const rate = sent ? (errors / sent) * 100 : 0
  return new Intl.NumberFormat(language, { maximumFractionDigits: 1 }).format(rate)
}

const NORMAL_HA = ['hot-standby', 'load-balancing', 'backup', 'passive-backup', 'ready']
const BAD_HA = ['partner-down', 'terminated', 'unavailable']

// HA pill tone, like the reference waypoints: the serving server ember, a healthy
// standby green, a backup gray, a broken pair red, a transition yellow.
export function haTone(h) {
  if (!h) return 'neutral'
  if (BAD_HA.includes(h.state) || h.partner?.in_touch === false) return 'danger'
  if (!NORMAL_HA.includes(h.state)) return 'warning'
  if (h.state === 'backup' || h.state === 'passive-backup' || h.role === 'backup') return 'neutral'
  if (h.role === 'primary' || h.state === 'load-balancing') return 'primary'
  return 'success'
}

// Rates as the tiles print them: one decimal under 10.
export const rateFormat = (lang) => (v) => new Intl.NumberFormat(lang, { maximumFractionDigits: v < 10 ? 1 : 0 }).format(v)

// "837" and "/s", or "1.24" and "k/s" past a thousand: the unit rolls with the digits.
export function splitRate(v, lang) {
  if (v === null || v === undefined) return { n: '-', u: '' }
  if (v >= 1000) return { n: new Intl.NumberFormat(lang, { minimumFractionDigits: 2, maximumFractionDigits: 2 }).format(v / 1000), u: 'k/s' }
  return { n: rateFormat(lang)(v), u: '/s' }
}

// Pools as the operator sees them: an HA pair reports each pool once per server, so the
// rows of one pool (engine, subnet, range) merge into one with the worst utilization of
// the pair; `node_ids` names every server that reported it, `node_id` the worst one (its
// pressure series and alerts are the ones shown). Sorted busiest first.
export function mergePools(pools) {
  const groups = new Map()
  for (const p of pools || []) {
    const key = `${p.engine}|${p.subnet_id}|${String(p.pool || '').replace(/\s+/g, '')}`
    const held = groups.get(key)
    if (!held) {
      groups.set(key, { ...p, node_ids: [p.node_id] })
      continue
    }
    const ids = held.node_ids.includes(p.node_id) ? held.node_ids : [...held.node_ids, p.node_id]
    const worse = (p.percent ?? 0) > (held.percent ?? 0)
    groups.set(key, { ...(worse ? p : held), node_ids: ids })
  }
  return [...groups.values()].sort((a, b) => b.percent - a.percent)
}

// Most recent lease by client last transaction time, or null.
export function latestLease(items) {
  let best = null
  let bestAt = -Infinity
  for (const l of items || []) {
    const at = l?.cltt ? Date.parse(l.cltt) : NaN
    if (Number.isFinite(at) && at > bestAt) {
      best = l
      bestAt = at
    }
  }
  return best
}
