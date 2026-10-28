// SPDX-License-Identifier: Apache-2.0
// Resolver health of the mock (architecture section 25): per node measures, root and TLD probes,
// resolver series, and the temporary forwarder fallback with its plans, deadline and return.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

// Built-in presets (quad9.net and developers.cloudflare.com, read on 2026-10-28).
export const RESOLVER_PRESETS = [
  { id: 'quad9', name: 'Quad9', forwarders: ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9'], tls_name: 'dns.quad9.net', filtering: true, builtin: true },
  { id: 'quad9_unfiltered', name: 'Quad9 (no filtering)', forwarders: ['9.9.9.10', '149.112.112.10', '2620:fe::10', '2620:fe::fe:10'], tls_name: 'dns10.quad9.net', filtering: false, builtin: true },
  { id: 'cloudflare', name: 'Cloudflare', forwarders: ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'], tls_name: 'one.one.one.one', filtering: false, builtin: true },
]
export const RESOLVER_METRICS = [
  'queries_out_per_second', 'timeouts_percent', 'retries_percent', 'latency_p50_ms', 'latency_p95_ms',
  'servfail_out_percent', 'servfail_clients_percent', 'lame_per_minute', 'edns0_fail_per_minute',
  'valfail_percent', 'cache_hit_percent', 'cache_nodes', 'cache_memory_bytes', 'lru_per_minute',
  'mismatch_per_minute', 'quota_per_minute',
]
const ROOT_LETTERS = 'abcdefghijklm'.split('')
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f:]+:[0-9a-f:]*)$/i

export function resolverHandlers(state, { Problem, invalid, createPlan }) {
  const now = Date.now()
  state.resolver ||= { fallback: null }
  const r = state.resolver
  const nodeIds = () => state.nodes.map((n) => n.peer.id)
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const settings = () => state.settings.resolver || {}
  const checks = () => state.settings.checks || {}
  const nodeHealth = (id, i) => ({
    node_id: id,
    sampled_at: iso(now - 30000),
    error: null,
    rates: { queries_out: 12.5 + i, timeouts_percent: 0.4, servfail_out_percent: 0.8, servfail_clients_percent: 0.3, valfail_percent: 0.01, cache_hit_percent: 82.5 },
    latency_ms: { p50: 24 + i, p95: 180 + 10 * i },
    cache: { nodes: 48210, memory_bytes: 31457280, lru_per_minute: 0 },
    roots: ROOT_LETTERS.map((l, j) => ({ letter: l, address: `198.51.100.${j + 1}`, family: 4, rtt_ms: 12 + j, ok: true, last_failure: null })),
    tlds: [...(settings().probe_tlds || ['com', 'net', 'org', 'arpa']), 'lan'].map((tld) => ({ tld, servers: 2, ok: tld !== 'lan', rtt_ms: tld === 'lan' ? null : 30, last_failure: tld === 'lan' ? iso(now - 300000) : null, served: tld === 'lan' })),
  })
  const thresholds = () => ({
    latency_p95_ms: { warning: checks().resolver_latency_warning_milliseconds, critical: checks().resolver_latency_critical_milliseconds, observed_max_7d: 410 },
    timeouts_percent: { warning: checks().resolver_timeouts_warning_percent, critical: checks().resolver_timeouts_critical_percent, observed_max_7d: 2.1 },
    tld_failures: { warning: checks().resolver_tld_failures, observed_max_7d: 1 },
    mismatch_count: { warning: checks().resolver_mismatch_warning_count, observed_max_7d: 3 },
    lru_per_minute: { info: checks().resolver_lru_info_per_minute, observed_max_7d: 0 },
  })
  const fallbackPlanFor = (user, after, kind) => {
    const targets = after.node_ids
    const changes = targets.flatMap((id) => [
      { op: 'replace', target: 'options/forward', before: kind === 'return' ? r.fallback.forward : r.fallback?.before?.[id]?.forward ?? null, after: kind === 'return' ? r.fallback.before[id]?.forward ?? null : after.forward, node_ids: [id] },
      { op: 'replace', target: 'options/forwarders', before: kind === 'return' ? r.fallback.forwarders : null, after: kind === 'return' ? r.fallback.before[id]?.forwarders ?? null : after.forwarders, node_ids: [id] },
    ])
    const nodes = targets.map(nameOf).join(', ')
    const summary_message = kind === 'return'
      ? { key: 'plan.resolver.return', params: { nodes } }
      : { key: 'plan.resolver.fallback', params: { nodes, forwarders: after.forwarders.join(', '), forward: after.forward, until: after.until } }
    const summary = kind === 'return'
      ? `resolve directly again on ${nodes}: forward and forwarders as before the fallback`
      : `send the queries of ${nodes} to ${after.forwarders.join(', ')} (forward ${after.forward}) until ${after.until}`
    return createPlan(state, user, {
      scope: 'dns.resolver',
      engine: 'bind',
      summary,
      summary_message,
      changes,
      diff: targets.map((id) => `--- ${nameOf(id)} named.conf options\n+++ ${nameOf(id)} named.conf options\n${kind === 'return' ? '-' : '+'}forward ${after.forward || r.fallback?.forward};\n${kind === 'return' ? '-' : '+'}forwarders { ${(after.forwarders || r.fallback?.forwarders || []).join('; ')}; };\n`).join(''),
      targets,
      tool: 'named-checkconf',
      requires_confirmation: true,
      apply: () => {
        if (kind === 'return') {
          r.fallback = null
        } else {
          r.fallback = { ...after, before: Object.fromEntries(targets.map((id) => [id, { forward: null, forwarders: null }])), returned: [], manual_change: false }
        }
        return 'named-checkconf, rndc reconfig'
      },
      rollback: () => { if (kind !== 'return') r.fallback = null },
    })
  }

  return {
    'GET /dns/resolver/health': ({ query }) => {
      const only = query.get('node_id')
      const ids = nodeIds().filter((id) => !only || id === only)
      return { nodes: ids.map(nodeHealth), unavailable: [], fallback: r.fallback, return_ready: Boolean(r.fallback), thresholds: thresholds(), presets: [...RESOLVER_PRESETS, ...(settings().presets || [])] }
    },
    'GET /series/resolver': ({ query }) => {
      const metric = query.get('metric') || 'latency_p95_ms'
      if (!RESOLVER_METRICS.includes(metric)) throw invalid('metric', `one of ${RESOLVER_METRICS.join(', ')}`)
      const only = query.get('node_id')
      const step = 300000
      return {
        series: nodeIds().filter((id) => !only || id === only).map((id, i) => ({
          key: { node_id: id, metric },
          points: Array.from({ length: 24 }, (_, k) => [Math.floor((now - (23 - k) * step) / 1000), Math.round((150 + 40 * Math.sin(k / 3) + 10 * i) * 10) / 10]),
        })),
      }
    },
    'POST /dns/resolver/fallback/plan': ({ body, user }) => {
      if (r.fallback) throw new Problem(409, 'conflict', 'a forwarder fallback is already active: return or extend it')
      const preset = body.preset ? [...RESOLVER_PRESETS, ...(settings().presets || [])].find((p) => p.id === body.preset) : null
      if (body.preset && !preset) throw invalid('preset', 'unknown preset')
      const forwarders = body.forwarders?.length ? body.forwarders : preset?.forwarders || []
      if (!forwarders.length) throw invalid('forwarders', 'at least one address')
      const bad = forwarders.find((a) => !IP_RE.test(a))
      if (bad) throw invalid('forwarders', `not an address: ${bad}`)
      const forward = body.forward || 'first'
      if (!['first', 'only'].includes(forward)) throw invalid('forward', 'first or only')
      const hours = body.hours ?? settings().fallback_max_hours ?? 24
      if (!Number.isInteger(hours) || hours < 1 || hours > (settings().fallback_max_hours ?? 24)) throw invalid('hours', `between 1 and ${settings().fallback_max_hours ?? 24}`)
      const ids = body.node_ids?.length ? body.node_ids : nodeIds()
      const unknown = ids.find((id) => !nodeIds().includes(id))
      if (unknown) throw invalid('node_ids', `unknown node ${unknown}`)
      const started = Date.now()
      return fallbackPlanFor(user, {
        id: ulid(started), node_ids: ids, preset: preset?.id || null, forwarders, forward, tls_name: body.tls_name ?? (body.tls ? preset?.tls_name : null) ?? null,
        started_at: iso(started), until: iso(started + hours * 3600000), by: user.username,
      }, 'fallback')
    },
    'POST /dns/resolver/fallback/return/plan': ({ user }) => {
      if (!r.fallback) throw new Problem(409, 'conflict', 'no forwarder fallback is active')
      return fallbackPlanFor(user, { node_ids: r.fallback.node_ids }, 'return')
    },
    'PUT /dns/resolver/fallback': ({ body, user }) => {
      if (!r.fallback) throw new Problem(409, 'conflict', 'no forwarder fallback is active')
      const until = Date.parse(body.until)
      const max = Date.now() + (settings().fallback_max_hours ?? 24) * 3600000
      if (!Number.isFinite(until) || until <= Date.now() || until > max) throw invalid('until', 'a time in the future, at most fallback_max_hours from now')
      r.fallback.until = iso(until)
      auditEntry(state, user, { action: 'dns.resolver.op', target: `resolver:fallback/${r.fallback.id}`, request: { op: 'extend', until: r.fallback.until } })
      return { fallback: r.fallback }
    },
  }
}
