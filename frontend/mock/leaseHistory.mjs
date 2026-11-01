// SPDX-License-Identifier: Apache-2.0
// Lease history of the mock (architecture section 15, Lease history): LeaseEvent rows derived from
// the mock leases, with the shapes of services/lease_history.py; GET /dhcp/{family}/leases/history
// and GET /hosts/{key}/timeline.
import { iso } from './data.mjs'

const HOUR = 3600000
const bareHex = (v) => String(v || '').toLowerCase().replace(/[:\-.\s]/g, '')
const pairs = (hex) => hex.match(/../g).join(':')

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

function event(lease, name, at, extra = {}) {
  const cltt = lease.cltt ? Date.parse(lease.cltt) : at
  const valid = lease.valid_lft || 3600
  return {
    ts: iso(at), event: name, engine: lease.family === 'v6' ? 'kea6' : 'kea4', family: lease.family,
    ip_address: lease.ip_address, lease_type: lease.lease_type ?? null, hw_address: lease.hw_address ?? null,
    duid: lease.duid ?? null, client_id: lease.client_id ?? null,
    hostname: lease.hostname ? String(lease.hostname).replace(/\.$/, '').toLowerCase() : null,
    subnet_id: lease.subnet_id, cltt: iso(cltt), valid_lft: valid, expires_at: iso(cltt + valid * 1000),
    state: 'default', nodes: [...new Set([lease.node_id, ...(extra.nodes || [])].filter(Boolean))].sort(),
    ...extra,
  }
}

// One `new` per address held now, a `renew` for every other one, and on the first address an
// earlier holder (`new`, `delete`) then the current one as `reassign`.
function build(state, family) {
  const now = Date.now()
  const seen = new Map()
  for (const l of state.leases[family] || []) {
    const key = `${l.ip_address}/${l.lease_type || ''}`
    const held = seen.get(key)
    if (held) held.nodes = [...new Set([...held.nodes, l.node_id])]
    else seen.set(key, { lease: l, nodes: [l.node_id] })
  }
  const rows = []
  ;[...seen.values()].forEach(({ lease, nodes }, i) => {
    const cltt = lease.cltt ? Date.parse(lease.cltt) : now - HOUR
    if (i === 0) {
      const before = { ...lease, hw_address: '02:00:5e:00:53:ff', duid: lease.duid ? '00:01:00:01:de:ad:be:ef' : null, hostname: 'old-laptop' }
      rows.push(event(before, 'new', cltt - 30 * HOUR, { nodes, cltt: iso(cltt - 30 * HOUR) }))
      rows.push(event(before, 'delete', cltt - 26 * HOUR, { nodes, cltt: iso(cltt - 30 * HOUR) }))
      rows.push(event(lease, 'reassign', cltt - 4 * HOUR, { nodes, cltt: iso(cltt - 4 * HOUR) }))
    } else {
      rows.push(event(lease, 'new', cltt - 4 * HOUR, { nodes, cltt: iso(cltt - 4 * HOUR) }))
    }
    if (i % 2 === 1) rows.push(event(lease, 'renew', cltt, { nodes }))
  })
  return rows.sort((a, b) => b.ts.localeCompare(a.ts))
}

export function leaseHistoryHandlers(state, { invalid, notFound }) {
  const time = (query, name) => {
    const raw = query.get(name)
    if (raw === null || raw === '') return null
    const ms = /^-?\d+$/.test(raw) ? Number(raw) * 1000 : Date.parse(raw)
    if (Number.isNaN(ms)) throw invalid(name, 'RFC 3339 or Unix seconds')
    return ms
  }
  const hexId = (query, name) => {
    const raw = query.get(name)
    if (!raw) return null
    const hex = bareHex(raw)
    if (!hex || hex.length % 2 || !/^[0-9a-f]+$/.test(hex)) throw invalid(name, 'hexadecimal octets')
    return pairs(hex)
  }
  const select = (family, f, query) => {
    const since = time(query, 'since')
    const until = time(query, 'until')
    if (since !== null && until !== null && since > until) throw invalid('since', '<= until')
    return build(state, family).filter((r) =>
      (!f.ip || r.ip_address === f.ip) && (!f.hw || r.hw_address === f.hw) && (!f.duid || r.duid === f.duid)
      && (!f.hostname || r.hostname === f.hostname)
      && (since === null || Date.parse(r.ts) >= since) && (until === null || Date.parse(r.ts) <= until)
      && (!f.node || r.nodes.includes(f.node)))
  }
  const v6On = () => Boolean(state.modules?.cluster?.dhcpv6)

  return {
    'GET /dhcp/{family}/leases/history': ({ params, query }) => {
      const f = {
        ip: query.get('ip')?.trim().toLowerCase() || null, hw: hexId(query, 'mac'), duid: hexId(query, 'duid'),
        hostname: query.get('hostname')?.trim().replace(/\.$/, '').toLowerCase() || null, node: query.get('node_id') || null,
      }
      const rows = select(params.family, f, query)
      return { ...paginate(rows, query), meta: { unavailable: [], truncated: false } }
    },
    'GET /hosts/{key}/timeline': ({ params, query }) => {
      const key = String(params.key)
      const [kind, ...rest] = key.split(':')
      const value = rest.join(':').trim().toLowerCase()
      let f
      let families = v6On() ? ['v4', 'v6'] : ['v4']
      if (kind === 'mac') {
        const hex = bareHex(value)
        if (!hex || hex.length % 2) throw invalid('key', 'mac:, ip: or name:')
        f = { hw: pairs(hex) }
      } else if (kind === 'ip') {
        if (!value) throw invalid('key', 'ip: needs a value')
        families = [value.includes(':') ? 'v6' : 'v4']
        if (families[0] === 'v6' && !v6On()) throw notFound(`host ${key}`)
        f = { ip: value }
      } else if (kind === 'name') {
        // A key always narrows the history (read:hosts alone never lists all of it).
        f = { hostname: value.replace(/\.$/, '') }
        if (!f.hostname) throw invalid('key', 'name: needs a value')
      } else {
        throw invalid('key', 'mac:, ip: or name:')
      }
      const rows = families.flatMap((family) => select(family, f, query))
        .map((r) => ({ source: 'lease', ...r }))
        .sort((a, b) => b.ts.localeCompare(a.ts))
      return { ...paginate(rows, query), meta: { key, unavailable: [], truncated: false } }
    },
  }
}
