// SPDX-License-Identifier: Apache-2.0
// Observed IPv6 addresses of the mock (architecture section 27): hosts with their observed
// addresses and classes, AAAA and PTR, the proposal, the watched prefixes and the source status.
// Exceptions (`mac:` and `addr:` keys of ipv6_missing_aaaa and ipv6_stale_aaaa) are read from the shared exception list.
import { iso } from './data.mjs'
import { auditEntry, unifiedDiff } from './plans.mjs'
import { expandIpv6, parsePrefix, prefix64, reverseZoneName } from '../src/pages/hosts/ipv6.js'

const FILTERS = ['missing_aaaa', 'missing_ptr', 'stale', 'unknown', 'random_mac']
const PREFIX_RE = /^[0-9a-f:]+\/(\d{1,3})$/i

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

export function ipv6Handlers(state, { Problem, invalid, createPlan, zonePlan }) {
  const now = Date.now()
  const day = 86400000
  state.ipv6 ||= {
    prefixes: [],
    hosts: [
      {
        // The hosts view key of 192.0.2.10, so the host card finds this row.
        host_key: 'ip:192.0.2.10', name: 'printer.example.lan.', mac: '02:00:5e:00:53:10', mac_random: false, ipv4: ['192.0.2.10'],
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
        // A prefix no reverse zone serves: its selection asks for the zone first.
        host_key: 'mac:02:00:5e:00:53:30', name: 'camera.example.lan.', mac: '02:00:5e:00:53:30', mac_random: false, ipv4: ['192.0.2.30'],
        observed: [{ address: '2001:db8:1::5eff:fe00:5330', class: 'unknown', sources: ['neighbors'], first_seen: iso(now - 2 * day), last_seen: iso(now - 600000) }],
        aaaa: [], ptr: [], proposal: null, excepted: false,
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
  // The served ip6.arpa zone of a view holding an address (longest match), as the plans read it.
  const servedZone = (address, view = '_default') => {
    const nibbles = expandIpv6(address)
    let best = null
    for (const z of state.zones || []) {
      if (!z.name?.endsWith('.ip6.arpa.') || (z.view || '_default') !== view) continue
      const head = z.name.slice(0, -'.ip6.arpa.'.length).split('.').reverse().join('')
      if (nibbles?.startsWith(head) && (!best || head.length > best.head)) best = { name: z.name, head: head.length }
    }
    return best?.name || null
  }
  const reverseMissing = (addresses, view) => {
    const zones = new Map()
    for (const a of addresses) {
      const prefix = v.prefixes.find((p) => parsePrefix(p) && expandIpv6(a)?.startsWith(parsePrefix(p).nibbles.slice(0, parsePrefix(p).len / 4))) || prefix64(a)
      zones.set(reverseZoneName(prefix), { prefix, zone: reverseZoneName(prefix), view })
    }
    const list = [...zones.values()]
    const p = new Problem(409, 'precondition_failed', `no reverse zone serves these addresses: create ${list.map((z) => z.zone).join(', ')} first`)
    p.extra = { reverse_zones: list }
    return p
  }
  const ptrName = (address) => `${[...expandIpv6(address)].reverse().join('.')}.ip6.arpa.`
  const recordPlan = (user, { summary, summary_message, changes, notes = [], confirm = false, apply, rollback }) => {
    const text = (side) => changes.filter((c) => c[side]).map((c) => `${c.name} 3600 IN ${c.rtype} ${c[side]}`).join('\n')
    return createPlan(state, user, {
      scope: 'dns.rrset',
      engine: 'bind',
      summary: [summary, ...notes].join('; '),
      summary_message,
      changes: changes.map((c) => ({ op: c.before ? (c.after ? 'replace' : 'delete') : 'add', target: `${c.zone}/${c.name}/${c.rtype}`, before: c.before ? { name: c.name, rtype: c.rtype, ttl: 3600, rdata: [c.before] } : null, after: c.after ? { name: c.name, rtype: c.rtype, ttl: 3600, rdata: [c.after] } : null, node_ids: [] })),
      diff: unifiedDiff(text('before'), text('after'), 'ipv6'),
      targets: [state.selfId],
      requires_confirmation: confirm,
      apply,
      rollback,
    })
  }
  const snapshot = () => JSON.parse(JSON.stringify(v.hosts))
  const restore = (saved) => { v.hosts = saved }

  function selectionPlan(body, user) {
    const items = body.items
    if (!Array.isArray(items) || !items.length) throw invalid('items', 'a non-empty list is required')
    if (items.length > 500) throw invalid('items', 'at most 500 items per plan')
    const errors = []
    const seen = new Set()
    const picked = []
    items.forEach((item, i) => {
      const host = v.hosts.find((h) => h.host_key === item?.host_key)
      const address = expandIpv6(item?.address) ? String(item.address).toLowerCase() : null
      if (!host) return errors.push({ field: `items[${i}].host_key`, message: `${item?.host_key} is not in the IPv6 view` })
      if (!address) return errors.push({ field: `items[${i}].address`, message: 'a global IPv6 address is required' })
      if (seen.has(address)) return errors.push({ field: `items[${i}].address`, message: `${address} is selected twice` })
      seen.add(address)
      const o = host.observed.find((x) => x.address === address)
      if (!o) return errors.push({ field: `items[${i}].address`, message: `${address} is not observed for ${host.host_key}` })
      if (o.class === 'temporary') return errors.push({ field: `items[${i}].address`, message: `${address} is a temporary address` })
      const name = item.name || host.proposal?.name || host.name
      if (!name) return errors.push({ field: `items[${i}].name`, message: `no name for ${host.host_key}` })
      picked.push({ host, address, name, o })
      return null
    })
    if (errors.length) throw new Problem(400, 'validation_error', 'invalid IPv6 plan', errors)
    const view = body.reverse_view || body.view || '_default'
    const uncovered = picked.filter((p) => !servedZone(p.address, view)).map((p) => p.address)
    if (uncovered.length) throw reverseMissing(uncovered, view)
    const changes = []
    for (const p of picked) {
      if (!p.host.aaaa.includes(p.address)) changes.push({ zone: 'example.lan.', name: p.name, rtype: 'AAAA', after: p.address })
      if (!p.host.ptr.includes(p.address)) changes.push({ zone: servedZone(p.address, view), name: ptrName(p.address), rtype: 'PTR', after: p.name })
    }
    if (!changes.length) throw new Problem(409, 'conflict', 'nothing to change: every address has its AAAA and PTR')
    const notes = []
    const random = picked.filter((p) => p.host.mac_random).map((p) => p.name)
    if (random.length) notes.push(`${random.join(', ')}: random MAC, the name may follow another device`)
    const unknown = picked.filter((p) => p.o.class === 'unknown').map((p) => p.address)
    if (unknown.length) notes.push(`${unknown.join(', ')}: not yet known as stable`)
    const saved = snapshot()
    return recordPlan(user, {
      summary: `AAAA and PTR of ${picked.length} IPv6 addresses`,
      summary_message: { key: 'plan.ipv6.aaaa', params: { count: picked.length } },
      changes,
      notes,
      apply() {
        for (const p of picked) {
          if (!p.host.aaaa.includes(p.address)) p.host.aaaa = [...p.host.aaaa, p.address]
          if (!p.host.ptr.includes(p.address)) p.host.ptr = [...p.host.ptr, p.address]
          if (p.host.proposal?.address === p.address) p.host.proposal = null
        }
        return `${changes.length} records written`
      },
      rollback() { restore(saved) },
    })
  }

  function replacePrefixPlan(body, user) {
    const errors = []
    const a = parsePrefix(body.old_prefix)
    const b = parsePrefix(body.new_prefix)
    if (!a || a.len < 16 || a.len > 124) errors.push({ field: 'old_prefix', message: 'an IPv6 prefix from /16 to /124' })
    if (!b || b.len < 16 || b.len > 124) errors.push({ field: 'new_prefix', message: 'an IPv6 prefix from /16 to /124' })
    if (a && b && a.len !== b.len) errors.push({ field: 'new_prefix', message: 'both prefixes have the same length' })
    if (a && b && a.nibbles === b.nibbles) errors.push({ field: 'new_prefix', message: 'the prefixes overlap' })
    if (errors.length) throw new Problem(400, 'validation_error', 'invalid prefix replacement', errors)
    const view = body.reverse_view || body.view || '_default'
    // Prefix lengths are whole nibbles in the mock.
    const keep = Math.ceil(a.len / 4)
    const under = (addr) => expandIpv6(addr).slice(0, keep) === a.nibbles.slice(0, keep)
    const moved = (addr) => {
      const n = (b.nibbles.slice(0, keep) + expandIpv6(addr).slice(keep)).match(/.{4}/g).join(':')
      return parsePrefix(`${n}/128`).text.split('/')[0]
    }
    const hits = v.hosts.flatMap((h) => h.aaaa.filter(under).map((addr) => ({ h, addr, to: moved(addr) })))
    if (!hits.length) throw new Problem(409, 'conflict', `no AAAA under ${a.text}`)
    const lost = hits.filter((x) => x.h.ptr.includes(x.addr) && servedZone(x.addr, view) && !servedZone(x.to, view))
    if (lost.length) {
      const p = new Problem(409, 'precondition_failed', `no reverse zone serves ${b.text}: create ${reverseZoneName(b.text)} first`)
      p.extra = { reverse_zones: [{ prefix: b.text, zone: reverseZoneName(b.text), view }] }
      throw p
    }
    const changes = hits.flatMap((x) => [
      { zone: 'example.lan.', name: x.h.name || 'example.lan.', rtype: 'AAAA', before: x.addr, after: x.to },
      ...(x.h.ptr.includes(x.addr) ? [{ zone: servedZone(x.addr, view), name: ptrName(x.addr), rtype: 'PTR', before: x.h.name }, { zone: servedZone(x.to, view), name: ptrName(x.to), rtype: 'PTR', after: x.h.name }] : []),
    ])
    const saved = snapshot()
    const zones = ['example.lan.']
    return recordPlan(user, {
      summary: `${a.text} replaced by ${b.text}: ${hits.length} AAAA addresses in ${zones.join(', ')}`,
      summary_message: { key: 'plan.ipv6.replace_prefix', params: { old_prefix: a.text, new_prefix: b.text, count: hits.length, zones } },
      changes,
      confirm: true,
      apply() {
        for (const x of hits) {
          x.h.aaaa = x.h.aaaa.map((addr) => (addr === x.addr ? x.to : addr))
          x.h.ptr = x.h.ptr.map((addr) => (addr === x.addr ? x.to : addr))
          x.h.stale = (x.h.stale || []).filter((addr) => addr !== x.addr)
        }
        return `${hits.length} AAAA moved`
      },
      rollback() { restore(saved) },
    })
  }

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
      if (query.get('host_key')) items = items.filter((h) => h.host_key === query.get('host_key'))
      if (query.get('zone')) items = items.filter((h) => h.proposal?.zone === query.get('zone') || h.name?.endsWith(query.get('zone')))
      return { ...paginate(items, query), meta: { unavailable: v.unavailable } }
    },
    'POST /hosts/ipv6/plan': ({ body, user }) => selectionPlan(body, user),
    'POST /hosts/ipv6/replace-prefix/plan': ({ body, user }) => replacePrefixPlan(body, user),
    'POST /hosts/ipv6/reverse-zone/plan': ({ body, user }) => {
      const p = parsePrefix(body.prefix)
      if (!p || p.len < 16 || p.len > 124) throw invalid('prefix', 'an IPv6 prefix from /16 to /124')
      const view = body.view || '_default'
      if (servedZone(`${p.text.split('/')[0]}`, view)) throw new Problem(409, 'conflict', `a served zone of view ${view} already holds ${p.text}`)
      const name = reverseZoneName(p.text)
      return zonePlan({ body: { change: { op: 'add', target: `${view}/${name}`, after: { name, kind: 'primary', view, file: `db.${name.slice(0, -1)}`, dynamic: true, ns: ['ns1.example.lan.', 'ns2.example.lan.'], update_policy: ['grant ddi-admin zonesub ANY'], allow_transfer: ['key ddi-read'], node_ids: body.node_ids || [] } } }, user })
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
