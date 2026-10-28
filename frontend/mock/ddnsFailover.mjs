// SPDX-License-Identifier: Apache-2.0
// DDNS failover of the mock (architecture section 24): the active primary of each dynamic zone,
// the D2 server lists, and the prepare, failover, switchover and replay plans.
import { iso } from './data.mjs'

export function ddnsFailoverHandlers(state, { Problem, invalid, createPlan, hasPermission }) {
  const nodes = () => state.nodes.map((n) => n.peer)
  const primary = () => nodes()[0]
  const dynamicZones = () => state.zones.filter((z) => z.kind === 'primary' && z.dynamic)
  state.ddnsRoles ||= Object.fromEntries(
    dynamicZones().map((z) => [`_default/${z.name}`, { primary: primary().id, epoch: 1, since: iso(Date.now() - 30 * 86400000), by: 'admin', prepared: false }]),
  )
  const roles = state.ddnsRoles
  const needBoth = (user, perms) => {
    const missing = perms.find((p) => !hasPermission(user, p))
    if (missing) throw new Problem(403, 'forbidden', `requires ${missing}`)
  }
  const selected = (zones) => {
    const keys = Object.keys(roles)
    if (!zones) return keys
    const wanted = zones.map((z) => (z.includes('/') ? z : `_default/${z.endsWith('.') ? z : `${z}.`}`))
    const unknown = wanted.find((k) => !keys.includes(k))
    if (unknown) throw invalid('zones', `not a dynamic zone: ${unknown}`)
    return wanted
  }
  const target = (id) => {
    const node = nodes().find((n) => n.id === id)
    if (!node) throw invalid('to_node_id', 'unknown node')
    return node
  }
  const servers = () => [primary(), ...nodes().slice(1)]

  return {
    'GET /dhcp/ddns/resilience': ({ user }) => {
      needBoth(user, ['read:dhcp', 'read:dns'])
      return {
        zones: Object.entries(roles).map(([key, r]) => {
          const [view, zone] = key.split('/')
          return {
            zone, view, primary_node_id: r.primary, epoch: r.epoch, since: r.since,
            copies: nodes().filter((n) => n.id !== r.primary).map((n) => n.id),
            ready: r.prepared && nodes().length > 1,
            blockers: nodes().length > 1 ? (r.prepared ? [] : [{ key: 'ddns.blocker.not_prepared', params: {} }]) : [{ key: 'ddns.blocker.single_node', params: {} }],
          }
        }),
        d2: nodes().filter((n) => n.modules?.d2 !== false).map((n) => ({
          node_id: n.id,
          domains: Object.keys(roles).map((key) => ({
            direction: key.endsWith('in-addr.arpa.') || key.endsWith('ip6.arpa.') ? 'reverse' : 'forward',
            name: key.split('/')[1],
            servers: servers().map((s) => ({ address: new URL(s.url).hostname, node_id: s.id, role: s.id === roles[key].primary ? 'primary' : 'secondary' })),
          })),
        })),
        outage: null,
        replay: { from: null, to: null, candidates: 0 },
      }
    },
    'POST /dhcp/ddns/resilience/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const keys = selected(body.zones)
      return createPlan(state, user, {
        scope: 'dns.failover',
        summary: `prepare DDNS failover for ${keys.length} zones`,
        changes: keys.map((k) => ({ op: 'replace', target: `ddns.roles/${k}`, before: null, after: { prepared: true } })),
        targets: nodes().map((n) => n.id),
        apply: () => keys.forEach((k) => { roles[k].prepared = true }),
        job: ['keys', 'd2-lists', 'roles'],
      })
    },
    'POST /dhcp/ddns/failover/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const to = target(body.to_node_id)
      const keys = selected(body.zones)
      if (keys.every((k) => roles[k].primary === to.id)) throw new Problem(409, 'conflict', `${to.name} is already the active primary`)
      return createPlan(state, user, {
        scope: 'dns.failover',
        summary: `promote ${to.name} primary of ${keys.length} zones`,
        changes: keys.map((k) => ({ op: 'replace', target: `ddns.roles/${k}`, before: { primary: roles[k].primary, epoch: roles[k].epoch }, after: { primary: to.id, epoch: roles[k].epoch + 1 } })),
        targets: nodes().map((n) => n.id),
        requires_confirmation: true,
        apply: () => keys.forEach((k) => Object.assign(roles[k], { primary: to.id, epoch: roles[k].epoch + 1, since: iso(Date.now()), by: user.username })),
        job: ['promote', 'd2-lists', 'roles'],
      })
    },
    'POST /dhcp/ddns/switchover/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const to = target(body.to_node_id)
      const keys = selected(body.zones)
      return createPlan(state, user, {
        scope: 'dns.failover',
        summary: `hand the primary role of ${keys.length} zones to ${to.name}`,
        changes: keys.map((k) => ({ op: 'replace', target: `ddns.roles/${k}`, before: { primary: roles[k].primary, epoch: roles[k].epoch }, after: { primary: to.id, epoch: roles[k].epoch + 1 } })),
        targets: nodes().map((n) => n.id),
        requires_confirmation: true,
        apply: () => keys.forEach((k) => Object.assign(roles[k], { primary: to.id, epoch: roles[k].epoch + 1, since: iso(Date.now()), by: user.username })),
        job: ['freeze', 'wait-serial', 'promote', 'demote', 'd2-lists', 'roles', 'replay'],
      })
    },
    'POST /dhcp/ddns/replay/plan': ({ body, user }) => {
      const family = body.family || 'v4'
      if (!['v4', 'v6'].includes(family)) throw invalid('family', 'v4 or v6')
      const leases = (state.leases?.[family] || []).filter((l) => l.hostname).slice(0, body.limit || 2000)
      if (!leases.length) throw new Problem(409, 'conflict', 'no lease to replay in the window')
      return createPlan(state, user, {
        scope: 'dhcp.lease',
        engine: family === 'v4' ? 'kea4' : 'kea6',
        summary: `resend DDNS for ${leases.length} leases`,
        changes: leases.map((l) => ({ op: 'replace', target: `resend/${l.ip_address}`, before: null, after: { hostname: l.hostname } })),
        requires_confirmation: true,
      })
    },
  }
}
