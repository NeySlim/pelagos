// SPDX-License-Identifier: Apache-2.0
// Cluster events on demand, so every contextual animation of the UI can be produced against
// the mock: a new lease, a pool alert that opens then resolves, a replication round, a zone
// transfer, an HA failover and failback, and the HA heartbeats that tick on their own.
// POST /api/v1/_mock/events {"kind": ...} runs one (mock only, no session needed).
import { iso, ulid } from './data.mjs'
import { notifyState } from './notify.mjs'
import { ddnsFailoverEvents } from './ddnsFailover.mjs'

export const EVENT_KINDS = ['lease', 'alert', 'alert-resolve', 'replication', 'transfer', 'ha-failover', 'ha-failback', 'heartbeat', 'alerts-peer', 'notify-fail', 'notify-recover', 'ddns-outage', 'ddns-return', 'ddns-demote']

const POOL = { family: 'v4', subnetId: 3, pool: '192.0.2.200 - 192.0.2.219', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219' }

export function poolHistoryKey(engine, subnetId, pool, nodeId) {
  return `${engine}|${subnetId}|${pool}|${nodeId}`
}

const timers = new Set()
function later(ms, fn) {
  const timer = setTimeout(() => {
    timers.delete(timer)
    fn()
  }, ms)
  timer.unref?.()
  timers.add(timer)
}

export function stopEventTimers() {
  for (const timer of timers) clearTimeout(timer)
  timers.clear()
}

// `zones` events of a change on this node's primary zone, as the collectors send them: the
// serial here at once, then one transfer per online secondary when its copy follows
// (relayed: the event carries the secondary's node id).
export function zoneEvents(state, emit, zoneName, delayMs = 0) {
  const zone = state.zones?.find?.((z) => z.name === zoneName) || { name: zoneName, view: '_default' }
  const serial = state.soaSerial?.(state.records?.[zoneName])
  if (typeof serial !== 'number') return
  const view = zone.view || '_default'
  emit('zones', 'serial', { zone: zoneName, view, kind: 'primary', serial, previous: serial - 1 })
  later(delayMs, () => {
    for (const n of state.nodes || []) {
      if (n.is_self || n.status !== 'online' || !n.peer?.modules?.bind) continue
      const kept = state.secondaries?.[`${view}/${zoneName}`]
      if (kept && !kept.includes(n.peer.id)) continue
      emit('zones', 'transfer', { zone: zoneName, view, kind: 'secondary', serial, previous: serial - 1, primary_node_id: state.selfId }, n.peer.id)
    }
  })
}

// The lease the collector's watch reports (collector.pollers.kea.lease_brief).
export function leaseBrief(l) {
  const keys = ['ip_address', 'subnet_id', 'family', 'hw_address', 'client_id', 'duid', 'hostname', 'state', 'valid_lft', 'cltt', 'expires_at', 'lease_type', 'prefix_len', 'node_id']
  return Object.fromEntries(keys.map((k) => [k, l[k] ?? null]))
}

// helpers: { emit, inPool4, poolRange, ipToInt, utilization, bumpSerial, findZone, liveHa }
export function createEvents(state, h) {
  const self = () => state.nodes.find((n) => n.is_self)
  const now = () => Date.now()

  function poolPoint() {
    const row = h.utilization(state, POOL.family, state.selfId).find((r) => r.subnet_id === POOL.subnetId && r.pool === POOL.pool)
    if (!row) return
    const key = poolHistoryKey('kea4', POOL.subnetId, POOL.pool, state.selfId)
    state.poolHistory ||= {}
    ;(state.poolHistory[key] ||= []).push([Math.floor(now() / 1000), row.assigned, row.total])
  }

  function freeAddress(subnetId) {
    const subnet = state.subnets.v4.find((s) => s.id === subnetId)
    const used = new Set(state.leases.v4.map((l) => l.ip_address))
    for (const p of subnet?.pools || []) {
      const [a, b] = h.poolRange(p.pool)
      for (let n = h.ipToInt(a); n <= h.ipToInt(b); n += 1) {
        const ip = [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')
        if (!used.has(ip)) return ip
      }
    }
    return null
  }

  function addLease(ip, subnetId, hostname) {
    const t = now()
    const mac = `02:00:5e:${[t >>> 16, t >>> 8, t].map((x) => (x & 255).toString(16).padStart(2, '0')).join(':')}`
    const valid = subnetId === 3 ? 900 : 3600
    // Every DHCPv4 server of the relationship holds it, backups included.
    for (const nodeId of state.nodes.filter((n) => n.peer.modules?.kea4 !== false).map((n) => n.peer.id)) {
      state.leases.v4.push({
        ip_address: ip, subnet_id: subnetId, family: 'v4', hw_address: mac, client_id: `01:${mac}`, duid: null,
        hostname, state: 'default', valid_lft: valid, cltt: iso(nodeId === state.nodeIds.ns1 ? t : t - 40), expires_at: iso(t + valid * 1000),
        fqdn_fwd: false, fqdn_rev: false, iaid: null, lease_type: null, prefix_len: null, preferred_lft: null, pool_id: 0, user_context: {}, node_id: nodeId, raw: {},
      })
    }
  }

  const leasesSummary = (fresh) => h.emit('leases', 'summary', { engine: 'kea4', active: state.leases.v4.filter((l) => l.node_id === state.selfId).length, new_since_last: fresh, expired_since_last: 0 })
  // The lease watch of this node: one `lease` event per new lease it holds.
  const leaseEvent = (ip) => {
    const l = state.leases.v4.find((x) => x.ip_address === ip && x.node_id === state.selfId)
    if (l) h.emit('leases', 'lease', { engine: 'kea4', family: 'v4', change: 'new', lease: leaseBrief(l) })
  }

  const handlers = {
    // A peer whose alerts cannot be read (down: true) or again readable: the cluster view degrades.
    'alerts-peer'({ node = 'ns2', down = true } = {}) {
      const peer = state.nodes.find((n) => n.peer.name === node)
      if (!peer) return null
      state.alertsUnavailable = (state.alertsUnavailable || []).filter((u) => u.node_id !== peer.peer.id)
      if (down) state.alertsUnavailable.push({ node_id: peer.peer.id, name: node, error: `node ${node} is offline: unreachable` })
      h.emit('alerts', 'updated', {})
      return { ok: true, unavailable: state.alertsUnavailable }
    },
    lease() {
      let subnetId = 1
      let ip = freeAddress(1)
      if (!ip) {
        subnetId = 2
        ip = freeAddress(2)
      }
      if (!ip) return { ok: false, detail: 'no free address' }
      addLease(ip, subnetId, `client-${ip.split('.').pop()}`)
      leaseEvent(ip)
      leasesSummary(1)
      return { ok: true, ip }
    },

    // The guest pool fills up: its last address is leased, the warning alert gives way to a
    // critical pool_full one, which opens.
    alert() {
      poolPoint()
      const ip = freeAddress(POOL.subnetId)
      if (ip) {
        addLease(ip, POOL.subnetId, `guest-${ip.split('.').pop()}`)
        leaseEvent(ip)
      }
      poolPoint()
      leasesSummary(1)
      for (const a of state.alerts) {
        if (a.subject === POOL.subject && a.state !== 'resolved') {
          a.state = 'resolved'
          a.resolved_at = iso(now())
          h.emit('alerts', 'resolved', a)
        }
      }
      const alert = {
        id: ulid(), kind: 'pool_full', severity: 'critical', state: 'open', node_id: state.selfId, engine: 'kea4', subject: POOL.subject,
        title: 'pool 192.0.2.200-192.0.2.219 of subnet 3 is 100% used',
        title_message: { key: 'alert.pool_usage', params: { pool: '192.0.2.200-192.0.2.219', subnet_id: 3, percent: '100' } },
        details: { subnet_id: 3, assigned: 20, total: 20, percent: 100 },
        first_seen: iso(now()), last_seen: iso(now()), acked_by: null, acked_at: null, resolved_at: null,
        reported_by: [state.selfId],
      }
      state.alerts.unshift(alert)
      h.emit('alerts', 'opened', alert)
      return { ok: true, id: alert.id }
    },

    // Two guests leave: the pool is back under the critical line and the alert resolves.
    'alert-resolve'() {
      const guests = state.leases.v4.filter((l) => l.subnet_id === POOL.subnetId && h.inPool4(l.ip_address, POOL.pool))
      const ips = [...new Set(guests.map((l) => l.ip_address))].slice(-2)
      state.leases.v4 = state.leases.v4.filter((l) => !ips.includes(l.ip_address))
      poolPoint()
      leasesSummary(0)
      const open = state.alerts.filter((a) => a.subject === POOL.subject && a.kind === 'pool_full' && a.state !== 'resolved')
      for (const a of open) {
        a.state = 'resolved'
        a.resolved_at = iso(now())
        a.last_seen = a.resolved_at
        h.emit('alerts', 'resolved', a)
      }
      return { ok: true, resolved: open.map((a) => a.id) }
    },

    // A channel has failed past checks.notification_failure_warning_minutes: it turns failing and
    // the sender raises notification_failed (cluster-wide, subject notify:<channel id>).
    'notify-fail'({ channel_id: channelId } = {}) {
      const n = notifyState(state)
      const c = n.channels.find((x) => x.id === (channelId || 'ch-ntfy')) || n.channels[0]
      if (!c) return { ok: false }
      const since = iso(now() - 45 * 60000)
      const error = 'HTTP 401: unauthorized'
      c.status = { ...c.status, state: 'failing', since, last_error: error }
      const batch = ulid()
      n.history.unshift({
        id: batch, ts: iso(now()), channel_id: c.id, channel_name: c.name, node_id: state.selfId, batch_id: batch, reason: 'events', alert_ids: [],
        events: [], result: 'failed', status: 401, duration_ms: 120, error,
      })
      const subject = `notify:${c.id}`
      let alert = state.alerts.find((a) => a.kind === 'notification_failed' && a.subject === subject && a.state !== 'resolved')
      if (!alert) {
        alert = {
          id: ulid(), kind: 'notification_failed', severity: 'warning', state: 'open', node_id: null, engine: null, subject,
          title: `notification channel ${c.name} has been failing since ${since}: ${error}`,
          title_message: { key: 'alert.notification_failed', params: { channel: c.name, since, error } },
          details: { channel: c.id, since, error, status: 401 },
          first_seen: iso(now()), last_seen: iso(now()), acked_by: null, acked_at: null, resolved_at: null,
          reported_by: [state.selfId],
        }
        state.alerts.unshift(alert)
        h.emit('alerts', 'opened', alert)
      }
      h.emit('system', 'notify', { channel_id: c.id, state: 'failing' })
      return { ok: true, id: alert.id, channel_id: c.id }
    },

    // The channel sends again: back to ok, its notification_failed alert resolves.
    'notify-recover'({ channel_id: channelId } = {}) {
      const n = notifyState(state)
      const c = n.channels.find((x) => x.id === (channelId || 'ch-ntfy'))
      if (!c) return { ok: false }
      c.status = { ...c.status, state: c.enabled ? 'ok' : 'disabled', since: iso(now()), last_error: null }
      const open = state.alerts.filter((a) => a.kind === 'notification_failed' && a.subject === `notify:${c.id}` && a.state !== 'resolved')
      for (const a of open) {
        a.state = 'resolved'
        a.resolved_at = iso(now())
        a.last_seen = a.resolved_at
        h.emit('alerts', 'resolved', a)
      }
      h.emit('system', 'notify', { channel_id: c.id, state: c.status.state })
      return { ok: true, resolved: open.map((a) => a.id) }
    },

    // A configuration change on this node, then the peers adopt it.
    replication({ delayMs = state.replicationMs ?? 1200 } = {}) {
      const me = self()
      me.config_version += 1
      me.audit_count += 1
      h.emit('system', 'replication', { node_id: me.peer.id, config_version: me.config_version, audit_count: me.audit_count })
      later(delayMs, () => {
        for (const n of state.nodes) {
          if (n.is_self || n.status !== 'online') continue
          n.config_version = me.config_version
          n.audit_count = me.audit_count
          h.emit('system', 'replication', { node_id: n.peer.id, config_version: n.config_version, audit_count: n.audit_count })
        }
      })
      return { ok: true, config_version: me.config_version }
    },

    // The zone changes on this node; its secondaries follow after a NOTIFY and an IXFR.
    transfer({ zone = 'example.lan.', delayMs = state.transferMs ?? 2500 } = {}) {
      const z = h.findZone(state, zone)
      h.bumpSerial(state.records[z.name])
      state.transferLag ||= {}
      state.transferLag[z.name] = now() + delayMs
      zoneEvents(state, h.emit, z.name, delayMs)
      return { ok: true, zone: z.name, serial: state.soaSerial(state.records[z.name]) }
    },

    'ha-failover'({ family = 'v4' } = {}) {
      const [primary, standby] = state.ha[family]
      primary.state = 'partner-down'
      primary.partner = { ...primary.partner, state: 'unavailable', in_touch: false, age: null }
      standby.state = 'unavailable'
      standby.partner = { ...standby.partner, in_touch: false }
      state.haOutage ||= {}
      state.haOutage[family] = true
      // Lease updates that cannot reach the partner pile up at the lease rate. The state did
      // not change, so the growth goes out as `unsent`, never as a `state` transition.
      const grow = () => {
        if (!state.haOutage?.[family]) return
        primary.unsent_update_count = Math.min(500, (primary.unsent_update_count || 0) + 1)
        primary.collected_at = iso(now())
        h.emit('ha', 'unsent', primary)
        later(state.unsentMs ?? 900, grow)
      }
      later(state.unsentMs ?? 900, grow)
      for (const s of state.ha[family]) h.emit('ha', 'state', s)
      return { ok: true }
    },

    'ha-failback'({ family = 'v4' } = {}) {
      const [primary, standby] = state.ha[family]
      if (state.haOutage) state.haOutage[family] = false
      primary.state = 'hot-standby'
      primary.partner = { ...primary.partner, state: 'hot-standby', in_touch: true, age: 0 }
      standby.state = 'hot-standby'
      standby.partner = { ...standby.partner, state: 'hot-standby', in_touch: true, age: 0 }
      primary.unsent_update_count = 0
      primary.collected_at = iso(now())
      standby.collected_at = iso(now())
      for (const s of state.ha[family]) h.emit('ha', 'state', s)
      return { ok: true }
    },

    // One HA status sample per server, what the heartbeat traces draw: each collector sends
    // it as `ha`/`heartbeat` (relayed to the other nodes, so it carries the server's node id),
    // and GET /dhcp/{family}/ha reads the same sample.
    heartbeat() {
      for (const family of ['v4', 'v6']) {
        for (const s of state.ha[family] || []) {
          if (s.state === 'unavailable') continue
          s.collected_at = iso(now())
          if (s.partner?.in_touch) s.partner.age = 0
          const sample = h.liveHa ? h.liveHa(s) : s
          h.emit('ha', 'heartbeat', sample, s.node_id)
        }
      }
      return { ok: true }
    },
  }

  Object.assign(handlers, ddnsFailoverEvents(state, { emit: h.emit, ulid }))

  return {
    run(kind, args = {}) {
      const fn = handlers[kind]
      if (!fn) return null
      return fn(args)
    },
  }
}
