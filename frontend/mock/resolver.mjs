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

// The fallback lives in state.resolverFallback (gone with a scenario switch); a root outage per
// node in state.resolverOutage (node id: {since}) and its end in state.resolverHealthy (node id: ms).
export function resolverHandlers(state, { Problem, invalid, createPlan }) {
  const fb = () => state.resolverFallback || null
  const nodeIds = () => state.nodes.filter((n) => n.peer.modules?.bind !== false).map((n) => n.peer.id)
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const settings = () => state.settings.resolver || {}
  const checks = () => state.settings.checks || {}
  const maxHours = () => settings().fallback_max_hours ?? 24
  const allPresets = () => [...RESOLVER_PRESETS, ...(settings().presets || []).map((p) => ({ tls_name: null, filtering: false, ...p, builtin: false }))]
  const nodeHealth = (id, i) => {
    const now = Date.now()
    const down = state.resolverOutage?.[id]
    const healthy = state.resolverHealthy?.[id]
    return {
      node_id: id,
      sampled_at: iso(now - 30000),
      error: null,
      rates: { queries_out: down ? 41.2 : 12.5 + i, timeouts_percent: down ? 64 : 0.4, servfail_out_percent: 0.8, servfail_clients_percent: down ? 38 : 0.3, valfail_percent: 0.01, cache_hit_percent: 82.5 },
      latency_ms: { p50: down ? 1400 : 24 + i, p95: down ? 2600 : 180 + 10 * i },
      cache: { nodes: 48210, memory_bytes: 31457280, lru_per_minute: 0 },
      roots: ROOT_LETTERS.flatMap((l, j) => [
        { letter: l, address: `198.51.100.${j + 1}`, family: 4, rtt_ms: down ? null : 12 + j, ok: !down, last_failure: down ? iso(now - 60000) : null },
        { letter: l, address: `2001:db8:53::${(j + 1).toString(16)}`, family: 6, rtt_ms: down ? null : 14 + j, ok: !down, last_failure: down ? iso(now - 60000) : null },
      ]),
      tlds: [...(settings().probe_tlds || ['com', 'net', 'org', 'arpa']), 'lan'].map((tld) => {
        const served = tld === 'lan'
        const ok = !down && !served
        return { tld, servers: 2, ok, rtt_ms: ok ? 30 : null, last_failure: ok ? null : iso(now - 300000), served }
      }),
      probes_healthy_since: down ? 'unhealthy' : healthy ? iso(healthy) : null,
      observed_max_7d: { latency_p95_ms: 410, timeouts_percent: 2.1, mismatch_per_minute: 0.1, lru_per_minute: 0, tld_failures: down ? 4 : 1 },
    }
  }
  const thresholds = () => ({
    latency_p95_ms: { warning: checks().resolver_latency_warning_milliseconds, critical: checks().resolver_latency_critical_milliseconds, observed_max_7d: 410 },
    timeouts_percent: { warning: checks().resolver_timeouts_warning_percent, critical: checks().resolver_timeouts_critical_percent, observed_max_7d: 2.1 },
    tld_failures: { warning: checks().resolver_tld_failures, observed_max_7d: 1 },
    mismatch_count: { warning: checks().resolver_mismatch_warning_count, observed_max_7d: 3 },
    lru_per_minute: { info: checks().resolver_lru_info_per_minute, observed_max_7d: 0 },
  })
  // As services.resolver_fallback.return_ready: every node still in the fallback healthy long enough.
  const returnReady = (entries) => {
    const f = fb()
    if (!f) return false
    const pending = f.node_ids.filter((id) => !f.returned.includes(id))
    const cutoff = Date.now() - (settings().fallback_return_healthy_minutes ?? 15) * 60000
    return pending.length > 0 && pending.every((id) => {
      const e = entries.find((x) => x.node_id === id)
      if (!e || ['unhealthy', 'unknown'].includes(e.probes_healthy_since)) return false
      return e.probes_healthy_since === null || Date.parse(e.probes_healthy_since) <= cutoff
    })
  }
  const options = () => ({ forward: state.resolver.forward ?? null, forwarders: state.resolver.forwarders?.length ? [...state.resolver.forwarders] : null })
  const written = (f) => f.forwarders.map((a) => (f.tls_name ? `${a} port 853 tls "${f.tls_name}"` : a))
  const fallbackPlanFor = (user, after, kind) => {
    const targets = kind === 'return' ? after.node_ids.filter((id) => !fb().returned.includes(id)) : after.node_ids
    const now = options()
    const changes = targets.flatMap((id) => {
      const back = kind === 'return' ? fb().before[id] || { forward: null, forwarders: null } : null
      return [
        { op: 'replace', target: 'options/forward', before: now.forward, after: kind === 'return' ? back.forward : after.forward, node_ids: [id] },
        { op: 'replace', target: 'options/forwarders', before: now.forwarders, after: kind === 'return' ? back.forwarders : written(after), node_ids: [id] },
      ]
    })
    const nodes = targets.map(nameOf).join(', ')
    const summary_message = kind === 'return'
      ? { key: 'plan.resolver.return', params: { nodes } }
      : { key: 'plan.resolver.fallback', params: { nodes, forwarders: after.forwarders.join(', '), forward: after.forward, until: after.until } }
    const summary = kind === 'return'
      ? `resolve directly again on ${nodes}: forward and forwarders as before the fallback`
      : `send the queries of ${nodes} to ${after.forwarders.join(', ')} (forward ${after.forward}) until ${after.until}`
    const block = (f) => `{ ${(f || []).join('; ')}; }`
    const diff = targets.map((id) => {
      const back = kind === 'return' ? fb().before[id] || {} : null
      const [fromFwd, toFwd] = kind === 'return' ? [now.forward, back.forward] : [now.forward, after.forward]
      const [fromList, toList] = kind === 'return' ? [now.forwarders, back.forwarders] : [now.forwarders, written(after)]
      const line = (sign, name, v) => (v === null || v === undefined ? '' : `${sign}${name} ${v};\n`)
      return `--- ${nameOf(id)} named.conf options\n+++ ${nameOf(id)} named.conf options\n${line('-', 'forward', fromFwd)}${line('-', 'forwarders', fromList && block(fromList))}${line('+', 'forward', toFwd)}${line('+', 'forwarders', toList && block(toList))}`
    }).join('')
    return createPlan(state, user, {
      scope: 'dns.resolver',
      engine: 'bind',
      summary,
      summary_message,
      changes,
      diff,
      targets,
      tool: 'named-checkconf',
      requires_confirmation: true,
      apply: () => {
        if (kind === 'return') {
          const back = fb().before[targets[0]] || {}
          state.resolver.forward = back.forward ?? null
          state.resolver.forwarders = back.forwarders ?? []
          state.resolverFallback = null
        } else {
          state.resolverFallback = { ...after, started_at: iso(Date.now()), before: Object.fromEntries(targets.map((id) => [id, now])), returned: [], manual_change: false }
          state.resolver.forward = after.forward
          state.resolver.forwarders = written(after)
        }
        return 'named-checkconf, rndc reconfig'
      },
      rollback: () => {
        if (kind !== 'return') {
          state.resolver.forward = now.forward
          state.resolver.forwarders = now.forwarders ?? []
          state.resolverFallback = null
        }
      },
    })
  }

  return {
    'GET /dns/resolver/health': ({ query }) => {
      const only = query.get('node_id')
      if (only && !nodeIds().includes(only)) throw new Problem(404, 'not_found', `node ${only} not found or does not run BIND`)
      const online = state.nodes.filter((n) => n.status !== 'offline').map((n) => n.peer.id)
      const ids = nodeIds().filter((id) => !only || id === only)
      const nodes = ids.filter((id) => online.includes(id)).map(nodeHealth)
      const unavailable = ids.filter((id) => !online.includes(id)).map((id) => ({ node_id: id, name: nameOf(id), error: 'peer did not answer' }))
      return { nodes, unavailable, fallback: fb(), return_ready: returnReady(nodes), thresholds: thresholds(), presets: allPresets() }
    },
    'GET /series/resolver': ({ query }) => {
      const metric = query.get('metric') || 'latency_p95_ms'
      if (!RESOLVER_METRICS.includes(metric)) throw invalid('metric', `one of ${RESOLVER_METRICS.join(', ')}`)
      const only = query.get('node_id')
      const to = Number(query.get('to')) || Math.floor(Date.now() / 1000)
      const from = Number(query.get('from')) || to - 86400
      const step = Math.max(60, Number(query.get('step')) || 300)
      const count = Math.min(400, Math.max(2, Math.floor((to - from) / step)))
      const base = { latency_p95_ms: 180, latency_p50_ms: 25, queries_out_per_second: 12, cache_hit_percent: 82, servfail_out_percent: 0.8, valfail_percent: 0.01, timeouts_percent: 0.4 }[metric] ?? 5
      return {
        series: nodeIds().filter((id) => !only || id === only).map((id, i) => ({
          key: { node_id: id, metric },
          points: Array.from({ length: count }, (_, k) => [to - (count - 1 - k) * step, Math.round(base * (1 + 0.2 * Math.sin(k / 3 + i)) * 100) / 100]),
        })),
        unavailable: [],
      }
    },
    'POST /dns/resolver/fallback/plan': ({ body, user }) => {
      if (fb()) throw new Problem(409, 'conflict', 'a forwarder fallback is already active: return or extend it')
      const preset = body.preset ? allPresets().find((p) => p.id === body.preset) : null
      if (body.preset && !preset) throw invalid('preset', 'unknown')
      const forwarders = body.forwarders?.length ? body.forwarders : preset?.forwarders || []
      if (!forwarders.length) throw invalid('forwarders', 'at least one address')
      const bad = forwarders.find((a) => !IP_RE.test(a))
      if (bad) throw invalid('forwarders', `not an address: ${bad}`)
      const forward = body.forward || 'first'
      if (!['first', 'only'].includes(forward)) throw invalid('forward', 'first or only')
      const hours = body.hours ?? maxHours()
      if (!Number.isInteger(hours) || hours < 1 || hours > maxHours()) throw invalid('hours', `1 to ${maxHours()}`)
      const tlsName = body.tls_name || (body.tls ? preset?.tls_name : null) || null
      if (body.tls && !tlsName) throw invalid('tls_name', 'required')
      const ids = body.node_ids?.length ? body.node_ids : nodeIds()
      const unknown = ids.find((id) => !nodeIds().includes(id))
      if (unknown) throw invalid('node_ids', `unknown node ${unknown}`)
      const built = Date.now()
      return fallbackPlanFor(user, {
        id: ulid(built), node_ids: ids, preset: preset?.id || null, forwarders, forward, tls_name: tlsName,
        started_at: null, until: iso(built + hours * 3600000), by: user.username,
      }, 'fallback')
    },
    'POST /dns/resolver/fallback/return/plan': ({ user }) => {
      if (!fb()) throw new Problem(409, 'conflict', 'no forwarder fallback is active')
      return fallbackPlanFor(user, { node_ids: fb().node_ids }, 'return')
    },
    'PUT /dns/resolver/fallback': ({ body, user }) => {
      const f = fb()
      if (!f) throw new Problem(409, 'conflict', 'no forwarder fallback is active')
      const raw = body.until
      const until = typeof raw === 'number' || /^\d+$/.test(String(raw)) ? Number(raw) * 1000 : Date.parse(raw)
      if (!Number.isFinite(until) || until <= Date.now() || until > Date.now() + maxHours() * 3600000) throw invalid('until', `future, at most ${maxHours()} hours`)
      f.until = iso(until)
      auditEntry(state, user, { action: 'dns.resolver.op', target: `resolver:fallback/${f.id}`, request: { op: 'extend', until: f.until } })
      return { fallback: f }
    },
  }
}

// /_mock/events kinds: the root servers stop answering one node (or every node), with the
// proposing alert resolver:roots; then they answer again, healthy since `minutes` ago.
export function resolverEvents(state, { emit, ulid: newId }) {
  const targets = (nodeId) => (nodeId ? [nodeId] : state.nodes.filter((n) => n.peer.modules?.bind !== false).map((n) => n.peer.id))
  return {
    'resolver-outage'({ node_id: nodeId } = {}) {
      state.resolverOutage ||= {}
      const ids = []
      for (const id of targets(nodeId)) {
        state.resolverOutage[id] = { since: Date.now() }
        if (state.resolverHealthy) delete state.resolverHealthy[id]
        if (state.alerts.some((a) => a.kind === 'resolver_health' && a.subject === 'resolver:roots' && a.node_id === id && a.state !== 'resolved')) continue
        const now = iso(Date.now())
        const alert = {
          id: newId(), kind: 'resolver_health', severity: 'critical', state: 'open', engine: 'bind', node_id: id, subject: 'resolver:roots',
          title: 'the resolver cannot reach the root servers', title_message: { key: 'alert.resolver_roots', params: {} },
          details: { remediation: 'resolver_fallback' }, first_seen: now, last_seen: now, acked_by: null, acked_at: null, resolved_at: null, reported_by: [id],
        }
        state.alerts.unshift(alert)
        emit('alerts', 'opened', alert)
        ids.push(alert.id)
      }
      return { ok: true, alerts: ids }
    },
    'resolver-recover'({ node_id: nodeId, minutes = 20 } = {}) {
      state.resolverHealthy ||= {}
      for (const id of targets(nodeId)) {
        if (state.resolverOutage) delete state.resolverOutage[id]
        state.resolverHealthy[id] = Date.now() - minutes * 60000
        for (const a of state.alerts.filter((x) => x.kind === 'resolver_health' && x.subject === 'resolver:roots' && x.node_id === id && x.state !== 'resolved')) {
          a.state = 'resolved'
          a.resolved_at = iso(Date.now())
          emit('alerts', 'resolved', a)
        }
      }
      return { ok: true }
    },
  }
}
