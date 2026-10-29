// SPDX-License-Identifier: Apache-2.0
// Observed IPv6 addresses of the mock (architecture section 27): hosts with their observed
// addresses and classes, AAAA and PTR, the proposal, the watched prefixes and the source status.
// Exceptions (`mac:` and `addr:` keys of ipv6_missing_aaaa and ipv6_stale_aaaa) are read from the shared exception list.
import { iso } from './data.mjs'
import { auditEntry } from './plans.mjs'

const FILTERS = ['missing_aaaa', 'missing_ptr', 'stale', 'unknown', 'random_mac']
const PREFIX_RE = /^[0-9a-f:]+\/(\d{1,3})$/i

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

export function ipv6Handlers(state, { invalid }) {
  const now = Date.now()
  const day = 86400000
  state.ipv6 ||= {
    prefixes: [],
    hosts: [
      {
        host_key: 'mac:02:00:5e:00:53:10', name: 'printer.example.lan.', mac: '02:00:5e:00:53:10', mac_random: false, ipv4: ['192.0.2.10'],
        observed: [{ address: '2001:db8::5eff:fe00:5310', class: 'eui64', sources: ['neighbors', 'dhcpv6'], first_seen: iso(now - 20 * day), last_seen: iso(now - 60000) }],
        aaaa: [], ptr: [], proposal: { address: '2001:db8::5eff:fe00:5310', class: 'eui64', name: 'printer.example.lan.', zone: 'example.lan.', reverse_zone: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.' }, excepted: false,
      },
      {
        host_key: 'mac:02:00:5e:00:53:11', name: 'laptop.example.lan.', mac: '02:00:5e:00:53:11', mac_random: false, ipv4: ['192.0.2.11'],
        observed: [
          { address: '2001:db8::1c2a:77ff:9d01:4e10', class: 'stable', sources: ['neighbors'], first_seen: iso(now - 9 * day), last_seen: iso(now - 3600000) },
          { address: '2001:db8::a4b9:12c3:5d6e:7f80', class: 'temporary', sources: ['neighbors'], first_seen: iso(now - day), last_seen: iso(now - 3600000) },
        ],
        aaaa: ['2001:db8::1c2a:77ff:9d01:4e10'], ptr: [], proposal: null, excepted: false,
      },
      {
        host_key: 'mac:06:11:22:33:44:55', name: null, mac: '06:11:22:33:44:55', mac_random: true, ipv4: [],
        observed: [{ address: '2001:db8::411:22ff:fe33:4455', class: 'unknown', sources: ['dhcpv6'], first_seen: iso(now - day), last_seen: iso(now - 600000) }],
        aaaa: [], ptr: [], proposal: null, excepted: false,
      },
      {
        host_key: 'mac:02:00:5e:00:53:20', name: 'nas.example.lan.', mac: '02:00:5e:00:53:20', mac_random: false, ipv4: ['192.0.2.20'],
        observed: [
          { address: '2001:db8::8a3f:2c19:b7e4:20d1', class: 'stable', sources: ['neighbors', 'dhcpv6'], first_seen: iso(now - 25 * day), last_seen: iso(now - 300000) },
          { address: '2001:db8::5a1:9e20', class: 'stable', sources: ['dhcpv6'], first_seen: iso(now - 29 * day), last_seen: iso(now - 20 * day) },
        ],
        // 2001:db8::20 is a service alias never seen next to a current address: never stale.
        aaaa: ['2001:db8::20', '2001:db8::5a1:9e20', '2001:db8::8a3f:2c19:b7e4:20d1'], ptr: ['2001:db8::20', '2001:db8::5a1:9e20', '2001:db8::8a3f:2c19:b7e4:20d1'], proposal: null, excepted: false,
        stale: ['2001:db8::5a1:9e20'],
      },
      {
        // AAAA at the apex nobody observed: a row from the zone, without MAC.
        host_key: 'name:example.lan.', name: 'example.lan.', mac: null, mac_random: false, ipv4: [],
        observed: [], aaaa: ['2001:db8::1', '2001:db8::2'], ptr: ['2001:db8::1'], proposal: null, excepted: false,
      },
    ],
    unavailable: [],
  }
  const v = state.ipv6
  const excepted = (key, kind = 'ipv6_missing_aaaa') => (state.exceptions || []).some((e) => e.kind === kind && e.key === key)
  // As services/ipv6_hosts.py: a host excepted by mac: is flagged, an address excepted by addr: is never
  // proposed; stale records excepted by mac: or addr: are left out of `stale`.
  // `current` as services/ipv6_hosts.py: eui64 or stable, seen within stable_min_days.
  const stableMs = (state.settings?.ipv6?.stable_min_days ?? 8) * day
  const isCurrent = (o) => ['eui64', 'stable'].includes(o.class) && now - Date.parse(o.last_seen) <= stableMs
  const row = (h) => ({
    ...h,
    observed: h.observed.map((o) => ({ ...o, current: isCurrent(o) })),
    excepted: h.mac ? excepted(`mac:${h.mac}`) : false,
    // The mock has no reverse zone outside 2001:db8::/64: every AAAA without its PTR is missing.
    ptr_missing: h.aaaa.filter((a) => !h.ptr.includes(a)),
    proposal: h.proposal && !excepted(`addr:${h.proposal.address}`) ? h.proposal : null,
    stale: excepted(`mac:${h.mac}`, 'ipv6_stale_aaaa') ? [] : (h.stale || []).filter((a) => !excepted(`addr:${a}`, 'ipv6_stale_aaaa')),
  })
  const status = () => [
    ...state.nodes.map((n) => ({ source: 'neighbors', source_id: null, node_id: n.peer.id, last_poll: iso(now - 60000), error: null, entries: 14, kept: 9, problem: null })),
    { source: 'dhcpv6', source_id: null, node_id: state.selfId, last_poll: iso(now - 120000), error: null, entries: 6, kept: 6, problem: null },
  ]
  const answer = () => ({
    prefixes: v.prefixes,
    effective_prefixes: [{ prefix: '2001:db8::/64', from: 'reverse_zone' }, ...v.prefixes.map((p) => ({ prefix: p, from: 'setting' }))],
    settings: { ...state.settings.ipv6 },
    status: status(),
  })
  return {
    'GET /hosts/ipv6': ({ query }) => {
      const filter = query.get('filter')
      if (filter && !FILTERS.includes(filter)) throw invalid('filter', `one of ${FILTERS.join(', ')}`)
      let items = v.hosts.map(row)
      if (filter === 'missing_aaaa') items = items.filter((h) => !h.excepted && h.proposal && !h.observed.some((o) => o.current && h.aaaa.includes(o.address)))
      if (filter === 'missing_ptr') items = items.filter((h) => h.ptr_missing.length)
      if (filter === 'stale') items = items.filter((h) => h.stale.length)
      if (filter === 'unknown') items = items.filter((h) => !h.name)
      if (filter === 'random_mac') items = items.filter((h) => h.mac_random)
      if (query.get('zone')) items = items.filter((h) => h.proposal?.zone === query.get('zone') || h.name?.endsWith(query.get('zone')))
      return { ...paginate(items, query), meta: { unavailable: v.unavailable } }
    },
    'GET /admin/ipv6': () => answer(),
    'PUT /admin/ipv6': ({ body, user }) => {
      const unknown = Object.keys(body).find((k) => !['prefixes', 'effective_prefixes', 'settings', 'status'].includes(k))
      if (unknown) throw invalid(unknown, 'unknown field')
      if ('prefixes' in body) {
        if (!Array.isArray(body.prefixes)) throw invalid('prefixes', 'list of IPv6 prefixes expected')
        const bad = body.prefixes.find((p) => !PREFIX_RE.test(p) || Number(p.split('/')[1]) > 128)
        if (bad) throw invalid('prefixes', `not an IPv6 prefix: ${bad}`)
        v.prefixes = [...body.prefixes]
      }
      auditEntry(state, user, { action: 'admin.ipv6.replace', target: 'ipv6', request: { prefixes: v.prefixes } })
      return answer()
    },
  }
}
