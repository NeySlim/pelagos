// SPDX-License-Identifier: Apache-2.0
// Live rates for the dashboard, derived from cumulative counters: BIND statistics
// (GET /dns/stats) and Kea statistic-get-all (GET /dhcp/{family}/stats). A rate needs
// two samples; a counter that goes back (daemon restart) rebases instead of going negative.

export const LIVE_INTERVAL_MS = 4000
export const LIVE_CAPACITY = 45
// Samples kept per source: a 5 min trace window plus a margin (charts show LIVE_CAPACITY).
export const LIVE_HISTORY = 80
// Two samples closer than this keep the older one: counter rounding over a few
// milliseconds would read as a spike.
export const MIN_SAMPLE_GAP_MS = LIVE_INTERVAL_MS / 2
// A live chart spans at least this many polls; fewer points sit at its right end.
export const LIVE_MIN_SLOTS = 8
export const RCODES = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0)

// Queries answered so far: the QUERY opcode, else the v4 and v6 request counters.
export function dnsCounters(stats) {
  if (!stats || typeof stats !== 'object') return null
  const query = stats.opcodes?.QUERY
  const total = query !== undefined && query !== null ? num(query) : num(stats.nsstats?.Requestv4) + num(stats.nsstats?.Requestv6)
  const parts = Object.fromEntries(RCODES.map((r) => [r, num(stats.rcodes?.[r])]))
  return { total, parts }
}

// Latest value of a Kea statistic: a list of [value, timestamp] samples, newest first.
export function keaCounter(statistics, name) {
  const samples = statistics?.[name]
  if (!Array.isArray(samples) || samples.length === 0) return null
  const first = samples[0]
  return num(Array.isArray(first) ? first[0] : first)
}

// The four packets of a lease exchange (DORA in v4, SARR in v6) and the v4 NAK.
export const DORA_COUNTERS = {
  v4: { discover: 'pkt4-discover-received', offer: 'pkt4-offer-sent', request: 'pkt4-request-received', ack: 'pkt4-ack-sent', nak: 'pkt4-nak-sent' },
  v6: { discover: 'pkt6-solicit-received', offer: 'pkt6-advertise-sent', request: 'pkt6-request-received', ack: 'pkt6-reply-sent' },
}
export const DORA_STEPS = ['discover', 'offer', 'request', 'ack']

// Leases handed out so far: ACKs (v4) or REPLYs (v6), with the received packets and the
// exchange steps beside.
export function dhcpCounters(res, family) {
  const st = res?.statistics
  if (!st || typeof st !== 'object') return null
  const v6 = family === 'v6'
  const total = keaCounter(st, v6 ? 'pkt6-reply-sent' : 'pkt4-ack-sent')
  const received = keaCounter(st, v6 ? 'pkt6-received' : 'pkt4-received')
  if (total === null && received === null) return null
  const parts = { received: received ?? 0 }
  for (const [step, name] of Object.entries(DORA_COUNTERS[v6 ? 'v6' : 'v4'])) {
    const v = keaCounter(st, name)
    if (v !== null) parts[step] = v
  }
  return { total: total ?? 0, parts }
}

// When a sample was taken: the server's collected_at when it parses, else the local clock.
export function sampleTime(stats, now) {
  const t = Date.parse(stats?.collected_at || '')
  return Number.isFinite(t) ? t : now
}

// Seconds a live chart of `count` points spans (stretched to LIVE_MIN_SLOTS, capped).
export function liveWindowSeconds(count, capacity = LIVE_CAPACITY) {
  const slots = Math.min(capacity, Math.max(count, LIVE_MIN_SLOTS))
  return Math.round(((slots - 1) * LIVE_INTERVAL_MS) / 1000)
}

// Left axis label of a live chart: "-30 s" under a minute, then "-3 min".
export function liveWindowLabel(t, count) {
  const seconds = liveWindowSeconds(count)
  return seconds < 60 ? t('live.agoSeconds', { seconds }) : t('live.ago', { minutes: Math.round(seconds / 60) })
}

export function appendPoint(points, point, capacity = LIVE_CAPACITY) {
  const out = [...(points || []), point]
  return out.length > capacity ? out.slice(out.length - capacity) : out
}

export const emptySource = () => ({ last: null, points: [], parts: {} })

// Feeds one sample { t, counters } into a source { last, points, parts }. The same
// snapshot twice, or a sample under `minGapMs` after the last, adds nothing; a counter
// reset rebases on the new sample.
export function advance(source, sample, capacity = LIVE_CAPACITY, minGapMs = MIN_SAMPLE_GAP_MS) {
  const state = source || emptySource()
  if (!sample?.counters) return state
  const last = state.last
  if (!last) return { ...state, last: sample }
  const dt = (sample.t - last.t) / 1000
  if (!(dt > 0) || dt * 1000 < minGapMs) return state
  const delta = sample.counters.total - last.counters.total
  if (delta < 0) return { ...state, last: sample }
  const points = appendPoint(state.points, { t: sample.t, v: delta / dt }, capacity)
  const parts = { ...state.parts }
  for (const [key, value] of Object.entries(sample.counters.parts || {})) {
    const before = last.counters.parts?.[key]
    if (before === undefined || value < before) continue
    parts[key] = appendPoint(parts[key], { t: sample.t, v: (value - before) / dt }, capacity)
  }
  return { last: sample, points, parts }
}

export const latest = (points) => (points?.length ? points[points.length - 1].v : null)

// Sums series point by point, aligned on their newest point (sources poll on the same tick).
export function combine(seriesList) {
  const lists = (seriesList || []).filter((s) => s?.length)
  if (lists.length === 0) return []
  const length = Math.max(...lists.map((s) => s.length))
  const out = []
  for (let i = 0; i < length; i += 1) {
    let v = 0
    let t = 0
    for (const s of lists) {
      const p = s[s.length - length + i]
      if (p) {
        v += p.v
        t = Math.max(t, p.t)
      }
    }
    out.push({ t, v })
  }
  return out
}

// Part shares of the newest rates, in percent (NXDOMAIN share of answers, for example).
export function share(parts, key) {
  const values = Object.values(parts || {}).map(latest).filter((v) => v !== null)
  const total = values.reduce((a, b) => a + b, 0)
  const own = latest(parts?.[key])
  return total > 0 && own !== null ? (own / total) * 100 : null
}

// Dashboard view of the polled sources: cluster series (summed over nodes), the newest
// DNS rate of each node, and the rcode series.
export function summarizeLive(targets, sources) {
  const of = (kind) => (targets || []).filter((t) => t.kind === kind)
  const src = (t) => sources?.[t.key]
  const dns = of('dns')
  const dhcp = of('dhcp')
  const dnsSeries = combine(dns.map((t) => src(t)?.points))
  const dhcpSeries = combine(dhcp.map((t) => src(t)?.points))
  const rcodes = Object.fromEntries(RCODES.map((r) => [r, combine(dns.map((t) => src(t)?.parts?.[r]))]))
  const byNode = {}
  const seriesByNode = {}
  for (const t of dns) {
    const v = latest(src(t)?.points)
    if (v !== null) byNode[t.node] = v
    seriesByNode[t.node] = src(t)?.points || []
  }
  const dora = Object.fromEntries([...DORA_STEPS, 'nak'].map((k) => [k, combine(dhcp.map((t) => src(t)?.parts?.[k]))]))
  return {
    dns: { enabled: dns.length > 0, series: dnsSeries, current: latest(dnsSeries), byNode, seriesByNode, rcodes },
    dhcp: { enabled: dhcp.length > 0, series: dhcpSeries, current: latest(dhcpSeries), dora },
  }
}

// The newest lease exchange of the DHCP series: per step rate, leases counted in the last
// sample interval, its instant, and whether NAKs were sent in it. Null before two samples.
export function latestExchange(dhcp) {
  const series = dhcp?.series || []
  const last = series[series.length - 1]
  const prev = series[series.length - 2]
  if (!last || !prev) return null
  const rates = Object.fromEntries(DORA_STEPS.map((k) => [k, latest(dhcp.dora?.[k])]))
  const nak = latest(dhcp.dora?.nak)
  return { t: last.t, rates, leases: Math.round((last.v * (last.t - prev.t)) / 1000), nak: nak !== null && nak > 0 }
}

// Drops points older than `maxAgeMs`, so a series restored after a pause does not join
// across the gap.
export function prune(source, now, maxAgeMs) {
  if (!source) return emptySource()
  const keep = (points) => (points || []).filter((p) => now - p.t <= maxAgeMs)
  const parts = Object.fromEntries(Object.entries(source.parts || {}).map(([k, v]) => [k, keep(v)]))
  const last = source.last && now - source.last.t <= maxAgeMs ? source.last : null
  return { last, points: keep(source.points), parts }
}
