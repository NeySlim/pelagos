// SPDX-License-Identifier: Apache-2.0
// GET /search in the mock (architecture section 17, Search), with the shapes of
// services/search_service.py: groups of { kind, id, label, sublabel, route }, names by substring,
// addresses by prefix, MAC, DUID and client ids by hex digits with or without separators.

const GROUPS = ['zones', 'records', 'leases', 'reservations', 'hosts', 'alerts', 'nodes', 'networks']
const GROUP_PERMISSION = {
  zones: 'read:dns', records: 'read:dns', leases: 'read:dhcp', reservations: 'read:dhcp',
  hosts: 'read:hosts', alerts: 'read:alerts', nodes: 'read:nodes', networks: 'read:hosts',
}
const SEARCH_PERMISSIONS = ['read:hosts', 'read:dns', 'read:dhcp']
const DNSSEC_TYPES = new Set(['SOA', 'NS', 'RRSIG', 'NSEC', 'NSEC3', 'DNSKEY', 'NSEC3PARAM', 'CDS', 'CDNSKEY'])
const DEFAULT_LIMIT = 8
const MAX_LIMIT = 50

const bareHex = (v) => String(v || '').toLowerCase().replace(/[:\-.\s]/g, '')

export function needle(q) {
  const text = String(q || '').trim().toLowerCase()
  const hex = bareHex(text)
  return { text, hex: hex.length >= 2 && /^[0-9a-f]+$/.test(hex) ? hex : null }
}

// 0 exact, 1 prefix, 2 substring, null: no match (same order as the backend).
export function score(row, n) {
  let best = null
  for (const v of row.names || []) {
    if (v === n.text) return 0
    if (v.startsWith(n.text)) best = 1
    else if (best === null && v.includes(n.text)) best = 2
  }
  for (const v of row.addresses || []) {
    if (v === n.text) return 0
    if (v.startsWith(n.text)) best = 1
  }
  if (n.hex) {
    for (const v of row.hexes || []) {
      if (v === n.hex) return 0
      if (v.startsWith(n.hex)) best = best === null || best > 1 ? 1 : best
      else if (best === null && v.includes(n.hex)) best = 2
    }
  }
  return best
}

const zoneRoute = (zone, view, q) => {
  const name = zone.replace(/\.$/, '')
  const params = new URLSearchParams()
  if (view && view !== '_default') params.set('view', view)
  if (q) params.set('q', q)
  const query = params.toString()
  return `/dns/zones/${name ? encodeURIComponent(name) : '@'}${query ? `?${query}` : ''}`
}
const withQ = (path, q) => `${path}?${new URLSearchParams({ q })}`

function best(rows, n, limit) {
  const scored = []
  for (const row of rows) {
    const s = score(row, n)
    if (s !== null) scored.push([s, row.result.label, row.result])
  }
  scored.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
  return [scored.slice(0, limit).map((s) => s[2]), scored.length]
}

export function searchHandlers(state, { Problem, invalid, hasPermission, buildHosts, leasesFor }) {
  const rows = {
    zones: () => state.zones.map((z) => {
      const view = z.view || '_default'
      return {
        result: { kind: 'zone', id: `${view}/${z.name}`, label: z.name, sublabel: view === '_default' ? z.kind : `${z.kind}, view ${view}`, route: zoneRoute(z.name, view) },
        names: [z.name.toLowerCase(), z.name.toLowerCase().replace(/\.$/, '')],
      }
    }),
    records: () => state.zones.flatMap((z) => (state.records[z.name] || [])
      .filter((r) => !DNSSEC_TYPES.has(r.rtype))
      .map((r) => {
        const address = r.rtype === 'A' || r.rtype === 'AAAA'
        const rdata = r.rdata.map((d) => String(d).toLowerCase())
        return {
          result: { kind: 'record', id: `${z.name}/${r.name}/${r.rtype}`, label: `${r.name} ${r.rtype}`, sublabel: r.rdata.slice(0, 3).join(', ') + (r.rdata.length > 3 ? ' ...' : ''), route: zoneRoute(z.name, null, r.name) },
          names: [r.name.toLowerCase(), r.name.toLowerCase().replace(/\.$/, ''), ...(address ? [] : rdata)],
          addresses: address ? rdata : [],
        }
      })),
    leases: () => ['v4', 'v6'].filter((f) => f === 'v4' || state.modules.cluster.dhcpv6).flatMap((family) => leasesFor(state, family).map((l) => {
      const ident = l.hw_address || l.duid || l.client_id || ''
      return {
        result: { kind: 'lease', id: `${family}:${l.ip_address}`, label: l.ip_address, sublabel: [l.hostname, ident].filter(Boolean).join(' '), route: withQ(`/dhcp/${family}/leases`, l.ip_address) },
        names: l.hostname ? [l.hostname.toLowerCase()] : [],
        addresses: [l.ip_address.toLowerCase()],
        hexes: [l.hw_address, l.duid, l.client_id].filter(Boolean).map(bareHex),
      }
    })),
    reservations: () => ['v4', 'v6'].filter((f) => f === 'v4' || state.modules.cluster.dhcpv6).flatMap((family) => state.reservations[family].map((r) => {
      const ips = r.ip_address ? [r.ip_address] : r.ip_addresses || []
      return {
        result: { kind: 'reservation', id: `${family}:${r.subnet_id}:${r.id_type}=${r.identifier.toLowerCase()}`, label: r.hostname || ips[0] || r.identifier, sublabel: [...ips.slice(0, 2), `${r.id_type}=${r.identifier}`].join(' '), route: withQ(`/dhcp/${family}/reservations`, r.identifier) },
        names: [r.hostname, r.identifier].filter(Boolean).map((v) => v.toLowerCase()),
        addresses: ips.map((ip) => ip.toLowerCase()),
        hexes: [bareHex(r.identifier)],
      }
    })),
    hosts: () => buildHosts(state).map((h) => {
      const value = h.hostname || h.ips[0] || h.mac || h.key
      return {
        result: { kind: 'host', id: h.key, label: h.hostname || value, sublabel: [...h.ips.slice(0, 2), ...(h.mac ? [h.mac] : [])].join(' '), route: withQ('/hosts', value.replace(/\.$/, '')) },
        names: h.hostname ? [h.hostname.toLowerCase()] : [],
        addresses: h.ips.map((ip) => ip.toLowerCase()),
        hexes: h.mac ? [bareHex(h.mac)] : [],
      }
    }),
    nodes: () => state.nodes.map((n) => ({
      result: { kind: 'node', id: n.peer.id, label: n.peer.name, sublabel: n.peer.url, route: '/nodes' },
      names: [n.peer.name, n.peer.id, n.peer.url].map((v) => String(v).toLowerCase()),
    })),
  }

  return {
    'GET /search': ({ query, user }) => {
      if (!SEARCH_PERMISSIONS.some((p) => hasPermission(user, p))) throw new Problem(403, 'forbidden', 'requires read:hosts, read:dns or read:dhcp')
      const raw = query.get('limit')
      let limit = DEFAULT_LIMIT
      if (raw !== null && raw !== '') {
        limit = Number(raw)
        if (!Number.isInteger(limit) || limit < 1) throw invalid('limit', 'integer')
        limit = Math.min(limit, MAX_LIMIT)
      }
      const q = query.get('q') || ''
      const n = needle(q.slice(0, 200))
      const results = Object.fromEntries(GROUPS.map((g) => [g, []]))
      const totals = Object.fromEntries(GROUPS.map((g) => [g, 0]))
      if (!n.text) return { q, limit, results, totals, errors: {} }
      for (const group of ['zones', 'records', 'leases', 'reservations', 'hosts', 'nodes']) {
        if (!hasPermission(user, GROUP_PERMISSION[group])) continue
        ;[results[group], totals[group]] = best(rows[group](), n, limit)
      }
      if (hasPermission(user, 'read:alerts')) {
        const open = state.alerts.filter((a) => a.state === 'open' && [a.title, a.subject, a.node_id, JSON.stringify(a.details || {})].some((v) => String(v || '').toLowerCase().includes(n.text)))
        results.alerts = open.slice(0, limit).map((a) => ({ kind: 'alert', id: a.id, label: a.title, sublabel: a.subject, route: `/alerts?${new URLSearchParams({ alert: a.id })}` }))
        totals.alerts = open.length
      }
      return { q, limit, results, totals, errors: {} }
    },
  }
}
