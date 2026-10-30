// SPDX-License-Identifier: Apache-2.0
// What the cluster trace tile shows, derived from the dashboard summary, the live rates,
// the measured heartbeats and the events lane: the two node cards and their link, the
// lanes of the trace and the readouts beside it.
import { beatStats } from '../../lib/trace'
import { partnerLost } from '../../lib/ha'

const ENGINES = [
  ['bind', 'BIND', 'dns'],
  ['kea4', 'DHCPv4', 'dhcp'],
  ['kea6', 'DHCPv6', 'dhcp'],
  ['d2', 'D2', 'ok'],
]

// This node first, then its first peer; the rest are counted.
export function topology(nodes = []) {
  const self = nodes.find((n) => n.is_self) || nodes[0] || null
  const others = nodes.filter((n) => n !== self)
  return { self, peer: others[0] || null, more: Math.max(0, others.length - 1) }
}

const ROLE_RANK = { primary: 0, secondary: 1, standby: 1, backup: 2 }
const ACTIVE = ['primary', 'secondary', 'standby']
const isOffline = (n) => Boolean(n?.status && n.status !== 'online')
// HA states in which a server answers no client.
const NOT_SERVING = ['unavailable', 'terminated', 'waiting', 'syncing', 'ready', 'in-maintenance', 'backup']

// A cluster of more than two nodes, for the mesh: every node card in order (the HA pair,
// primary first, then its backups, then the other nodes, this node first among equals),
// each with its HA role, and the links between them: replication between every two nodes,
// HA between the two active servers, a lease update feed from the active server to each
// backup. A link is down when a node at either end is offline, or the HA servers lost touch.
export function meshModel(nodes = [], ha = []) {
  const family = haFamilies(ha)[0] || null
  const states = ha.filter((h) => h.family === family && h.enabled !== false)
  const stateOf = (id) => states.find((h) => h.node_id === id) || null
  const rank = (n) => ROLE_RANK[stateOf(n.peer.id)?.role] ?? 3
  const cards = [...nodes]
    .sort((a, b) => rank(a) - rank(b) || (b.is_self ? 1 : 0) - (a.is_self ? 1 : 0) || String(a.peer.name).localeCompare(String(b.peer.name)))
    .map((node) => {
      const st = stateOf(node.peer.id)
      return { node, id: node.peer.id, role: st?.role || null, state: st?.state || null, server: st?.server_name || null }
    })
  const links = []
  for (let i = 0; i < cards.length; i += 1) {
    for (let j = i + 1; j < cards.length; j += 1) {
      const down = isOffline(cards[i].node) || isOffline(cards[j].node)
      links.push({ kind: 'repl', a: cards[i].id, b: cards[j].id, state: down ? 'down' : 'ok' })
    }
  }
  const active = cards.filter((c) => ACTIVE.includes(c.role))
  const primary = active.find((c) => c.role === 'primary') || active[0] || null
  const partnerName = primary && stateOf(primary.id)?.partner?.server_name
  const partner = active.find((c) => c !== primary && (!partnerName || c.server === partnerName)) || null
  if (primary && partner) {
    const lost = [primary, partner].some((c) => partnerLost(stateOf(c.id)?.partner) || isOffline(c.node))
    links.push({ kind: 'ha', a: primary.id, b: partner.id, state: lost ? 'down' : 'ok' })
  }
  // The server that sends the lease updates: the primary, or its partner while it serves alone.
  const serving = (c) => Boolean(c) && !isOffline(c.node) && !NOT_SERVING.includes(c.state)
  const feeder = serving(primary) ? primary : serving(partner) ? partner : primary
  for (const c of cards.filter((x) => x.role === 'backup')) {
    if (!feeder) break
    const down = isOffline(c.node) || isOffline(feeder.node) || (c.state && c.state !== 'backup')
    links.push({ kind: 'feed', a: feeder.id, b: c.id, state: down ? 'down' : 'ok' })
  }
  return { family, cards, links }
}

// The line under the mesh: every node in sync, the nodes behind this one's configuration,
// or the ones unreachable (those first).
export function meshStatus(self, nodes = []) {
  const others = nodes.filter((n) => n !== self)
  const offline = others.filter(isOffline)
  if (offline.length) return { status: 'unreachable', names: offline.map((n) => n.peer.name), count: offline.length }
  const a = self?.config_version
  const behind = others
    .map((n) => ({ name: n.peer.name, by: typeof a === 'number' && typeof n.config_version === 'number' ? Math.max(0, a - n.config_version) : 0 }))
    .filter((x) => x.by > 0)
  if (behind.length) return { status: 'behind', names: behind.map((x) => x.name), count: Math.max(...behind.map((x) => x.by)) }
  return { status: 'inSync', names: [], count: nodes.length }
}

// Engines a node runs, from its modules (all when it publishes none).
export function nodeEngines(node, { dhcpv6 = true } = {}) {
  const m = node?.peer?.modules
  return ENGINES.filter(([key]) => (key !== 'kea6' || dhcpv6) && (!m || m[key] !== false)).map(([key, label, tone]) => ({ key, label, tone }))
}

// HA families of the cluster that are configured.
export function haFamilies(ha = []) {
  return ['v4', 'v6'].filter((f) => ha.some((h) => h.family === f && h.enabled !== false))
}

// The link between this node and its peer: down when the peer is offline or an HA pair
// lost touch; else how far the peer's configuration is behind.
export function linkOf(self, peer, ha = []) {
  if (!self || !peer) return null
  const offline = peer.status && peer.status !== 'online'
  const lost = ha.some((h) => h.enabled !== false && partnerLost(h.partner))
  if (offline || lost) return { state: 'down', status: 'unreachable', behind: 0 }
  const a = self.config_version
  const b = peer.config_version
  const behind = typeof a === 'number' && typeof b === 'number' ? Math.max(0, a - b) : 0
  return { state: 'ok', status: behind ? 'behind' : 'inSync', behind }
}

// The heartbeat record the trace follows for a family: this node's view of its partner,
// else any server of that family.
export function heartbeatOf(heartbeats, family, selfId) {
  if (!heartbeats) return null
  return heartbeats[`${family}:${selfId}`] || Object.entries(heartbeats).find(([k]) => k.startsWith(`${family}:`))?.[1] || null
}

// Lanes of the cluster trace: DNS queries (line), DHCP leases (bars), HA heartbeats (one
// ECG row per family), events. A lane without its data source is left out.
export function traceLanes({ live, heartbeats, events, families = [], selfId, labels, format }) {
  const lanes = []
  if (live?.dns?.enabled) {
    lanes.push({ type: 'line', key: 'dns', color: 'dns', label: labels.dns, readoutLabel: labels.dnsUnit, data: live.dns.series || [], format: format.dns })
  }
  if (live?.dhcp?.enabled) {
    lanes.push({ type: 'bars', key: 'dhcp', color: 'dhcp', label: labels.dhcp, readoutLabel: labels.dhcpUnit, data: live.dhcp.series || [], format: format.dhcp })
  }
  if (families.length) {
    lanes.push({
      type: 'ecg',
      key: 'hb',
      label: labels.hb,
      rows: families.map((f) => {
        const rec = heartbeatOf(heartbeats, f, selfId)
        return { label: f, beats: rec?.beats || [], lost: rec?.lost || [], outage: rec?.outage || null }
      }),
    })
  }
  lanes.push({ type: 'events', key: 'events', label: labels.events, data: events || [] })
  return lanes
}

// Heartbeat readout: mean interval and jitter of the first family, its HA state, or the
// outage since when the partner was lost.
export function heartbeatReadout(heartbeats, families, selfId) {
  const fam = families[0]
  const rec = fam ? heartbeatOf(heartbeats, fam, selfId) : null
  if (!rec) return null
  if (rec.inTouch === false) return { lost: true, since: rec.outage?.from ?? null, state: rec.state }
  const st = beatStats(rec.beats)
  return { lost: false, mean: st?.mean ?? null, sd: st?.sd ?? null, state: rec.state, family: fam }
}

// Offset of a server clock running ahead of this browser, from the newest sample and the
// moment it arrived, so samples never sit in the future. An older sample is drawn where
// it belongs: its age is real.
export function clockOffset(sampleT, arrivedAt) {
  if (!Number.isFinite(sampleT) || !Number.isFinite(arrivedAt)) return 0
  return Math.max(0, sampleT - arrivedAt)
}
