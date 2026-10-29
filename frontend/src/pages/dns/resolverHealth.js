// SPDX-License-Identifier: Apache-2.0
// Resolver health (architecture section 25): the per node readings, root and TLD probe rows,
// the series ranges, and the fallback form (defaults, checks, request body) and its state.

export const DEFAULT_MAX_HOURS = 24
export const CUSTOM_PRESET = 'custom'

// Range of the history chart: span and step in seconds.
export const RANGES = {
  '1h': { seconds: 3600, step: 60 },
  '24h': { seconds: 86400, step: 900 },
  '7d': { seconds: 7 * 86400, step: 3600 },
}

// Metrics the history chart offers, with the unit their value carries.
export const CHART_METRICS = {
  latency_p95_ms: 'ms',
  queries_out_per_second: 'perSecond',
  timeouts_percent: 'percent',
  servfail_clients_percent: 'percent',
  valfail_percent: 'percent',
  cache_hit_percent: 'percent',
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null)

// warning/critical tone of a value against its thresholds (higher is worse).
export function toneOf(value, threshold) {
  const v = num(value)
  if (v === null || !threshold) return 'neutral'
  if (num(threshold.critical) !== null && v >= threshold.critical) return 'danger'
  if (num(threshold.warning) !== null && v >= threshold.warning) return 'warning'
  return 'success'
}

// The five readings of one node: outgoing queries, p95, SERVFAIL to clients, DNSSEC failures,
// cache hit rate. value null when never measured.
export function nodeReadings(entry, thresholds = {}) {
  const rates = entry?.rates || {}
  const p95 = num(entry?.latency_ms?.p95)
  const cache = num(rates.cache_hit_percent)
  return [
    { key: 'queriesOut', value: num(rates.queries_out), unit: 'perSecond', tone: 'neutral' },
    { key: 'p95', value: p95, unit: 'ms', tone: toneOf(p95, thresholds.latency_p95_ms) },
    // No threshold of these two reaches the health answer: kept neutral rather than guessed.
    { key: 'servfail', value: num(rates.servfail_clients_percent), unit: 'percent', tone: 'neutral' },
    { key: 'valfail', value: num(rates.valfail_percent), unit: 'percent', tone: 'neutral' },
    { key: 'cacheHit', value: cache, unit: 'percent', tone: 'neutral' },
  ]
}

// One row per root letter: its IPv4 and IPv6 probes side by side, the best time, the last failure.
export function rootRows(entry) {
  const byLetter = new Map()
  for (const r of entry?.roots || []) {
    const row = byLetter.get(r.letter) || { letter: r.letter, v4: null, v6: null, rtt_ms: null, ok: false, last_failure: null }
    const family = r.family === 6 || String(r.address || '').includes(':') ? 'v6' : 'v4'
    row[family] = { address: r.address, ok: Boolean(r.ok), rtt_ms: num(r.rtt_ms) }
    if (r.ok) row.ok = true
    if (r.ok && num(r.rtt_ms) !== null && (row.rtt_ms === null || r.rtt_ms < row.rtt_ms)) row.rtt_ms = r.rtt_ms
    if (r.last_failure && (!row.last_failure || Date.parse(r.last_failure) > Date.parse(row.last_failure))) row.last_failure = r.last_failure
    byLetter.set(r.letter, row)
  }
  return [...byLetter.values()].sort((a, b) => String(a.letter).localeCompare(String(b.letter)))
}

// Root letters that answer, out of the letters probed.
export function rootsAnswering(entry) {
  const rows = rootRows(entry)
  return { ok: rows.filter((r) => r.ok).length, total: rows.length }
}

// Series of one metric as chart rows: [{ ts (ms), [node_id]: value }], ascending.
export function chartRows(series) {
  const byTime = new Map()
  for (const s of series || []) {
    const node = s.key?.node_id
    for (const [ts, value] of s.points || []) {
      const t = typeof ts === 'number' ? ts * 1000 : Date.parse(ts)
      if (!Number.isFinite(t) || !node) continue
      const row = byTime.get(t) || { ts: t }
      row[node] = value
      byTime.set(t, row)
    }
  }
  return [...byTime.values()].sort((a, b) => a.ts - b.ts)
}

export function seriesQuery(metric, range, nodeId, nowMs = Date.now()) {
  const r = RANGES[range] || RANGES['24h']
  const to = Math.floor(nowMs / 1000)
  return { metric, node_id: nodeId || undefined, from: to - r.seconds, to, step: r.step }
}

// Hours the fallback form and the extension offer, up to fallback_max_hours.
export function hourChoices(maxHours = DEFAULT_MAX_HOURS) {
  const most = Math.max(1, Math.floor(Number(maxHours) || DEFAULT_MAX_HOURS))
  return [...new Set([1, 2, 4, 8, 12, 24, 48, 72, 168].filter((h) => h < most).concat(most))]
}

// nodeIds: the answering nodes only; a silent node ticked would make the API refuse the plan.
export function fallbackDefaults(presets = [], nodeIds = [], maxHours = DEFAULT_MAX_HOURS) {
  const first = presets[0]
  return {
    preset: first ? first.id : CUSTOM_PRESET,
    forwarders: first ? [...first.forwarders] : [],
    forward: 'first',
    node_ids: [...nodeIds],
    hours: Math.min(DEFAULT_MAX_HOURS, maxHours) || DEFAULT_MAX_HOURS,
    tls: false,
    tls_name: '',
  }
}

// What picking a preset puts in the form: its addresses, and DNS over TLS off when it names no host.
export function applyPreset(form, presets, id) {
  const preset = presets.find((p) => p.id === id)
  if (!preset) return { ...form, preset: CUSTOM_PRESET }
  return { ...form, preset: id, forwarders: [...preset.forwarders], tls: preset.tls_name ? form.tls : false, tls_name: '' }
}

const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/
// The fallback takes bare addresses (no port, no scope id): the TLS port is set by the plan.
export function validAddress(value) {
  const v = String(value || '').trim()
  if (V4.test(v)) return true
  if (!v.includes(':') || v.includes('%') || !/^[0-9a-f:.]+$/i.test(v)) return false
  const halves = v.split('::')
  if (halves.length > 2) return false
  const groups = halves.flatMap((h) => (h ? h.split(':') : []))
  const tail = groups[groups.length - 1] || ''
  const v4tail = V4.test(tail)
  const hex = v4tail ? groups.slice(0, -1) : groups
  if (!hex.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false
  const width = hex.length + (v4tail ? 2 : 0)
  return halves.length === 2 ? width < 8 : width === 8
}

const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$/i

// Field errors as message keys of the dns namespace; empty when the form can build a plan.
export function fallbackErrors(form, maxHours = DEFAULT_MAX_HOURS) {
  const errors = {}
  if (!form.forwarders?.length) errors.forwarders = 'resolverHealth.form.errors.forwarders'
  else if (form.forwarders.some((a) => !validAddress(a))) errors.forwarders = 'resolverHealth.form.errors.address'
  if (!form.node_ids?.length) errors.node_ids = 'resolverHealth.form.errors.nodes'
  const h = Number(form.hours)
  if (!Number.isInteger(h) || h < 1 || h > maxHours) errors.hours = 'resolverHealth.form.errors.hours'
  if (form.tls && form.preset === CUSTOM_PRESET && !HOST.test(String(form.tls_name || '').trim())) errors.tls_name = 'resolverHealth.form.errors.tlsName'
  return errors
}

// Body of POST /dns/resolver/fallback/plan. A preset goes by id; its TLS host is resolved by the API.
export function fallbackBody(form, allNodeIds = []) {
  const body = {
    forwarders: form.forwarders.map((a) => String(a).trim()),
    forward: form.forward === 'only' ? 'only' : 'first',
    hours: Number(form.hours),
  }
  const everyNode = allNodeIds.length > 0 && allNodeIds.every((id) => form.node_ids.includes(id)) && form.node_ids.length === allNodeIds.length
  if (!everyNode) body.node_ids = [...form.node_ids]
  if (form.preset && form.preset !== CUSTOM_PRESET) {
    body.preset = form.preset
    if (form.tls) body.tls = true
  } else if (form.tls) {
    body.tls = true
    body.tls_name = String(form.tls_name).trim()
  }
  return body
}

// Active fallback as the banner shows it: nodes still forwarding, time left, deadline passed.
export function fallbackStatus(fallback, nowMs = Date.now()) {
  if (!fallback) return null
  const until = Date.parse(fallback.until)
  const returned = fallback.returned || []
  return {
    pending: (fallback.node_ids || []).filter((id) => !returned.includes(id)),
    returned,
    remainingMs: Number.isFinite(until) ? until - nowMs : null,
    overdue: Number.isFinite(until) && until <= nowMs,
  }
}

// Remaining time as { hours, minutes } (floored), null when unknown or past.
export function remaining(ms) {
  if (ms === null || ms === undefined || ms <= 0) return null
  const minutes = Math.floor(ms / 60000)
  return { hours: Math.floor(minutes / 60), minutes: minutes % 60 }
}

// New deadline of PUT /dns/resolver/fallback: `hours` from now, RFC 3339, one minute short so a
// browser clock slightly ahead of the node stays within fallback_max_hours.
export const EXTEND_MARGIN_MS = 60000
export const extendUntil = (hours, nowMs = Date.now()) => new Date(nowMs + Number(hours) * 3600000 - EXTEND_MARGIN_MS).toISOString()

// Cluster digest for the dashboard tile: the worst p95 and SERVFAIL share, the root reachability,
// the fallback, and an overall tone.
export function resolverSummary(health) {
  if (!health) return null
  const nodes = health.nodes || []
  const thresholds = health.thresholds || {}
  const worst = (pick) => nodes.reduce((acc, n) => (num(pick(n)) !== null && (acc === null || pick(n) > acc) ? pick(n) : acc), null)
  const p95 = worst((n) => n.latency_ms?.p95)
  const servfail = worst((n) => n.rates?.servfail_clients_percent)
  const unhealthy = nodes.filter((n) => n.probes_healthy_since === 'unhealthy').length
  const measured = nodes.filter((n) => !n.error).length
  const latency = toneOf(p95, thresholds.latency_p95_ms)
  const tone = unhealthy > 0 || latency === 'danger'
    ? 'danger'
    : latency === 'warning' || health.fallback || (health.unavailable || []).length > 0
      ? 'warning'
      : measured > 0
        ? 'success'
        : 'neutral'
  return { p95, servfail, latencyTone: latency, unhealthy, nodes: nodes.length, measured, unavailable: (health.unavailable || []).length, fallback: health.fallback || null, returnReady: Boolean(health.return_ready), tone }
}
