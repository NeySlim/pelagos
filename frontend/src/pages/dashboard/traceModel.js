// SPDX-License-Identifier: Apache-2.0
// What the cluster trace tile shows, derived from the dashboard summary, the live rates,
// the measured heartbeats and the events lane: the two node cards and their link, the
// lanes of the trace and the readouts beside it.
import { beatStats } from '../../lib/trace'

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
  const lost = ha.some((h) => h.enabled !== false && h.partner?.in_touch === false)
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
