// SPDX-License-Identifier: Apache-2.0
// The HA relationship form: Kea ARM (2.6 and 3.x) roles per mode, a draft from the relationship
// read on the nodes or from the cluster's nodes, the promotion of a backup, and the body of
// POST /dhcp/{family}/ha/setup/plan.

export const MODES = ['hot-standby', 'load-balancing', 'passive-backup']
// Roles each mode takes, with how many: [at least, at most].
export const MODE_ROLES = {
  'hot-standby': { primary: [1, 1], standby: [1, 1], backup: [0, Infinity] },
  'load-balancing': { primary: [1, 1], secondary: [1, 1], backup: [0, Infinity] },
  'passive-backup': { primary: [1, 1], backup: [1, Infinity] },
}
// The partner role of the primary in each mode (none in passive-backup).
const PARTNER_ROLE = { 'hot-standby': 'standby', 'load-balancing': 'secondary', 'passive-backup': null }
// The port of the ha hook's listener when a node has no server yet.
export const DEFAULT_PORT = { v4: 8001, v6: 8002 }

function hostOf(url) {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

const hostPart = (host) => (host.includes(':') ? `[${host}]` : host)

// A draft from the relationship the nodes run (GET /dhcp/{family}/ha `relationships`).
export function draftFromRelationship(rel) {
  return {
    mode: rel.mode || 'hot-standby',
    servers: rel.servers.map((s) => ({ name: s.name, url: s.url || '', role: s.role, node_id: s.node_id || '', auto_failover: s.auto_failover ?? null })),
  }
}

// A draft for nodes without HA: the first two DHCP nodes as the pair, the others as backups.
export function draftForNodes(nodes, family) {
  const engine = family === 'v6' ? 'kea6' : 'kea4'
  const dhcp = (nodes || []).filter((n) => n.peer?.modules?.[engine] !== false)
  const ordered = [...dhcp.filter((n) => n.is_self), ...dhcp.filter((n) => !n.is_self)]
  return {
    mode: 'hot-standby',
    servers: ordered.map((n, i) => ({
      name: n.peer.name,
      url: `http://${hostPart(hostOf(n.peer.url || n.peer.web_url || '') || n.peer.name)}:${DEFAULT_PORT[family] || 8001}/`,
      role: i === 0 ? 'primary' : i === 1 ? 'standby' : 'backup',
      node_id: n.peer.id,
      auto_failover: null,
    })),
  }
}

// Roles follow a mode change: the primary stays, its partner takes the mode's partner role,
// anything the mode does not take becomes a backup.
export function withMode(draft, mode) {
  const partner = PARTNER_ROLE[mode]
  let partnered = false
  const servers = draft.servers.map((s) => {
    if (s.role === 'primary') return s
    if (partner && !partnered && ['standby', 'secondary'].includes(s.role)) {
      partnered = true
      return { ...s, role: partner }
    }
    return { ...s, role: 'backup' }
  })
  return { ...draft, mode, servers }
}

// Promote a backup: it takes the role of the active server that is lost (not in touch,
// else the partner of the primary), which becomes a backup.
export function promoteDraft(rel, backupName) {
  const draft = draftFromRelationship(rel)
  const lost =
    rel.servers.find((s) => s.role !== 'backup' && (s.in_touch === false || ['unavailable', 'terminated'].includes(s.state))) ||
    rel.servers.find((s) => s.role !== 'backup' && s.role !== 'primary') ||
    rel.servers.find((s) => s.role === 'primary')
  if (!lost) return draft
  return {
    ...draft,
    servers: draft.servers.map((s) => {
      if (s.name === backupName) return { ...s, role: lost.role }
      if (s.name === lost.name) return { ...s, role: 'backup' }
      return s
    }),
  }
}

// { field: message key } of a draft; empty when Kea would take it.
export function validateHaSetup(draft) {
  const errors = {}
  const roles = MODE_ROLES[draft.mode]
  if (!roles) return { mode: 'ha.setup.errors.mode' }
  if (draft.servers.length < 2) errors.servers = 'ha.setup.errors.twoServers'
  const names = new Set()
  const urls = new Set()
  const nodes = new Set()
  const counts = {}
  draft.servers.forEach((s, i) => {
    const name = String(s.name || '').trim()
    if (!name || /\s/.test(name)) errors[`servers[${i}].name`] = 'ha.setup.errors.name'
    else if (names.has(name)) errors[`servers[${i}].name`] = 'ha.setup.errors.duplicate'
    names.add(name)
    const url = String(s.url || '').trim()
    if (!/^https?:\/\/[^/\s]+/.test(url)) errors[`servers[${i}].url`] = 'ha.setup.errors.url'
    else if (urls.has(url)) errors[`servers[${i}].url`] = 'ha.setup.errors.duplicate'
    urls.add(url)
    if (s.node_id) {
      if (nodes.has(s.node_id)) errors[`servers[${i}].node_id`] = 'ha.setup.errors.nodeTwice'
      nodes.add(s.node_id)
    }
    if (!roles[s.role]) errors[`servers[${i}].role`] = 'ha.setup.errors.role'
    else counts[s.role] = (counts[s.role] || 0) + 1
  })
  if (!errors.servers) {
    for (const [role, [low, high]] of Object.entries(roles)) {
      const n = counts[role] || 0
      if (n < low || n > high) {
        errors.servers = role === 'backup' ? 'ha.setup.errors.backupNeeded' : 'ha.setup.errors.roleCount'
        errors.role = role
        break
      }
    }
  }
  if (!errors.servers && !nodes.size) errors.servers = 'ha.setup.errors.noNode'
  return errors
}

// POST /dhcp/{family}/ha/setup/plan body.
export function setupBody(draft) {
  return {
    mode: draft.mode,
    servers: draft.servers.map((s) => ({
      name: String(s.name).trim(),
      url: String(s.url).trim(),
      role: s.role,
      ...(s.node_id ? { node_id: s.node_id } : {}),
      ...(typeof s.auto_failover === 'boolean' ? { auto_failover: s.auto_failover } : {}),
    })),
  }
}

// The relationship is healthy when the active servers are in their mode's state and in
// touch, and every backup is in the backup state. A server no node runs and no partner
// reports (a backup elsewhere) says nothing either way.
export function relationshipHealthy(rel) {
  if (!rel?.servers?.length) return false
  const known = rel.servers.filter((s) => s.managed !== false || s.state)
  return known.every((s) => (s.role === 'backup' ? s.state === 'backup' : s.state === rel.mode && s.in_touch !== false))
}
