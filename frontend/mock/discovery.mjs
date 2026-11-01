// SPDX-License-Identifier: Apache-2.0
// IPv4 neighbor discovery of the mock (architecture section 27, IPv4 neighbors and discovery), with
// the shapes of services/discovery_service.py: GET /hosts/discovered, GET /hosts/vendor/{mac}, and
// Host.seen / Host.vendor on the hosts join.
import { iso } from './data.mjs'

const MINUTE = 60000
// A few real OUI entries (pelagos/data/oui.tsv holds the whole IEEE list).
const OUI = { B827EB: 'Raspberry Pi Foundation', '00000C': 'Cisco Systems', F01898: 'Apple', '3C5AB4': 'Google', '8C1F64AFA': 'DATA ELECTRONIC DEVICES' }
const MAC_RE = /^[0-9a-f]{1,2}([:-][0-9a-f]{1,2}){5}$/

export function normalizeMac(value) {
  const text = String(value || '').trim().toLowerCase()
  if (!MAC_RE.test(text)) return null
  const mac = text.split(/[:-]/).map((p) => p.padStart(2, '0')).join(':')
  return mac === '00:00:00:00:00:00' ? null : mac
}

export const macRandom = (mac) => Boolean(parseInt(mac.slice(0, 2), 16) & 2)

export function vendorEntry(mac) {
  const norm = normalizeMac(mac)
  if (!norm || macRandom(norm)) return null
  const hex = norm.replace(/:/g, '').toUpperCase()
  for (const size of [9, 7, 6]) if (OUI[hex.slice(0, size)]) return { prefix: hex.slice(0, size), vendor: OUI[hex.slice(0, size)] }
  return null
}

const enabled = (state) => Boolean(state.modules?.cluster?.discovery)

// NeighborObservation rows: the v4 lease holders seen by the node of their lease, plus devices
// nobody declared (a Raspberry Pi, a switch) and one excepted by the admin.
function neighbors(state) {
  if (state.discoveryNeighbors) return state.discoveryNeighbors
  const now = Date.now()
  const rows = (state.leases?.v4 || []).slice(0, 12).map((l, i) => ({
    family: 4, mac: l.hw_address, address: l.ip_address, node_id: l.node_id || state.selfId,
    first: now - (3 + i) * 24 * 60 * MINUTE, last: now - (i % 3) * MINUTE, state: i % 4 === 3 ? 'stale' : 'reachable',
  })).filter((r) => r.mac)
  const other = state.nodeIds?.ns2 || state.selfId
  rows.push(
    { family: 4, mac: 'b8:27:eb:5a:01:22', address: '192.0.2.231', node_id: state.selfId, first: now - 5 * 60 * MINUTE, last: now - MINUTE, state: 'reachable' },
    { family: 4, mac: 'b8:27:eb:5a:01:22', address: '192.0.2.231', node_id: other, first: now - 4 * 60 * MINUTE, last: now - 2 * MINUTE, state: 'reachable' },
    { family: 4, mac: '00:00:0c:9f:f0:01', address: '192.0.2.1', node_id: state.selfId, first: now - 40 * 24 * 60 * MINUTE, last: now, state: 'reachable' },
    { family: 4, mac: '3a:11:7f:00:42:10', address: '192.0.2.232', node_id: other, first: now - 20 * MINUTE, last: now - 3 * MINUTE, state: 'delay' },
  )
  state.discoveryNeighbors = rows.map(({ first, last, ...r }) => ({ ...r, first_seen: Math.floor(first / 1000), last_seen: Math.floor(last / 1000) }))
  return state.discoveryNeighbors
}

function devices(state) {
  const out = new Map()
  for (const n of neighbors(state)) {
    const dev = out.get(n.mac) || { mac: n.mac, addresses: new Map(), first_seen: n.first_seen, last_seen: n.last_seen, node_id: n.node_id, nodes: [] }
    dev.first_seen = Math.min(dev.first_seen, n.first_seen)
    if (n.last_seen > dev.last_seen) Object.assign(dev, { last_seen: n.last_seen, node_id: n.node_id })
    if (!dev.nodes.includes(n.node_id)) dev.nodes.push(n.node_id)
    const held = dev.addresses.get(n.address)
    if (!held) dev.addresses.set(n.address, { address: n.address, node_id: n.node_id, first_seen: n.first_seen, last_seen: n.last_seen, state: n.state })
    else if (n.last_seen > held.last_seen) Object.assign(held, { last_seen: n.last_seen, node_id: n.node_id, state: n.state })
    out.set(n.mac, dev)
  }
  for (const dev of out.values()) dev.nodes.sort()
  return out
}

const ts = (s) => iso(s * 1000)

// Host.seen and Host.vendor, as HostsService.collect_records sets them (null without the module).
export function decorateHosts(state, hosts) {
  for (const host of hosts) {
    host.seen = null
    host.vendor = null
  }
  if (!enabled(state)) return hosts
  const devs = devices(state)
  for (const host of hosts) {
    host.vendor = vendorEntry(host.mac)?.vendor ?? null
    let rows
    if (host.mac && devs.has(host.mac)) {
      const d = devs.get(host.mac)
      rows = [{ first_seen: d.first_seen, last_seen: d.last_seen, node_id: d.node_id }]
    } else {
      rows = [...devs.values()].flatMap((d) => [...d.addresses.values()]).filter((a) => host.ips.includes(a.address))
    }
    if (!rows.length) continue
    const latest = rows.reduce((a, b) => (b.last_seen > a.last_seen ? b : a))
    host.seen = { first: ts(Math.min(...rows.map((r) => r.first_seen))), last: ts(latest.last_seen), node: latest.node_id }
  }
  return hosts
}

export function discoveryHandlers(state, { Problem, invalid, buildHosts, paginate }) {
  const guard = () => {
    if (!enabled(state)) throw new Problem(404, 'module_disabled', 'module discovery is disabled')
  }
  const excepted = (mac) => (state.ptr?.exceptions?.() || []).some((e) => e.kind === 'unknown_device' && e.key === `mac:${mac}`)
  return {
    'GET /hosts/discovered': ({ query }) => {
      guard()
      const filter = query.get('filter')
      if (filter && !['unknown', 'known'].includes(filter)) throw invalid('filter', 'one of unknown, known')
      const needle = (query.get('q') || '').trim().toLowerCase()
      const hosts = buildHosts(state)
      const byMac = new Map(hosts.filter((h) => h.mac).map((h) => [h.mac, h.key]))
      const byIp = new Map(hosts.flatMap((h) => h.ips.map((ip) => [ip, h.key])))
      const rows = [...devices(state).values()]
        .sort((a, b) => b.last_seen - a.last_seen || a.mac.localeCompare(b.mac))
        .map((d) => {
          const addresses = [...d.addresses.values()].sort((a, b) => b.last_seen - a.last_seen)
          const key = byMac.get(d.mac) || addresses.map((a) => byIp.get(a.address)).find(Boolean) || null
          return {
            mac: d.mac, vendor: vendorEntry(d.mac)?.vendor ?? null, mac_random: macRandom(d.mac),
            addresses: addresses.map((a) => ({ ...a, first_seen: ts(a.first_seen), last_seen: ts(a.last_seen) })),
            first_seen: ts(d.first_seen), last_seen: ts(d.last_seen), nodes: d.nodes,
            host_key: key, unknown: key === null, excepted: excepted(d.mac),
          }
        })
        .filter((r) => filter !== 'unknown' || (r.unknown && !r.excepted))
        .filter((r) => filter !== 'known' || !r.unknown)
        .filter((r) => !needle || r.mac.includes(needle) || r.addresses.some((a) => a.address.includes(needle)) || (r.vendor || '').toLowerCase().includes(needle))
      return paginate(rows, query, { unavailable: [], errors: {} })
    },
    'GET /hosts/vendor/{mac}': ({ params }) => {
      guard()
      const mac = normalizeMac(params.mac)
      if (!mac) throw invalid('mac', `not a MAC address: ${params.mac}`)
      const found = vendorEntry(mac)
      return { mac, vendor: found?.vendor ?? null, prefix: found?.prefix ?? null }
    },
  }
}
