// SPDX-License-Identifier: Apache-2.0
// Observed IPv6 addresses of the mock (architecture section 27): hosts with their observed
// addresses and classes, AAAA and PTR, the proposal, and the observation sources with a test.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

const SOURCE_TYPES = ['opnsense']
const SOURCE_SECRETS = ['api_key', 'api_secret']
const FILTERS = ['missing_aaaa', 'missing_ptr', 'stale', 'unknown', 'random_mac']
const PREFIX_RE = /^[0-9a-f:]+\/(\d{1,3})$/i

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

export function ipv6Handlers(state, { Problem, invalid }) {
  const now = Date.now()
  const day = 86400000
  state.ipv6 ||= {
    sources: [{ id: 'src-router', type: 'opnsense', name: 'Router', url: 'https://router.example.lan', verify_tls: true, ca_pem: null, enabled: true, secrets: { api_key: 'k', api_secret: 's' } }],
    prefixes: [],
    hosts: [
      {
        host_key: 'mac:02:00:5e:00:53:10', name: 'printer.example.lan.', mac: '02:00:5e:00:53:10', mac_random: false, ipv4: ['192.0.2.10'],
        observed: [{ address: '2001:db8::5eff:fe00:5310', class: 'eui64', sources: ['neighbors', 'opnsense'], first_seen: iso(now - 20 * day), last_seen: iso(now - 60000) }],
        aaaa: [], ptr: [], proposal: { name: 'printer.example.lan.', zone: 'example.lan.', reverse_zone: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.' }, excepted: false,
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
        observed: [{ address: '2001:db8::411:22ff:fe33:4455', class: 'unknown', sources: ['opnsense'], first_seen: iso(now - day), last_seen: iso(now - 600000) }],
        aaaa: [], ptr: [], proposal: null, excepted: false,
      },
    ],
  }
  const v = state.ipv6
  const publicSource = (s) => ({ ...s, secrets: Object.fromEntries(SOURCE_SECRETS.map((k) => [k, Boolean(s.secrets?.[k])])) })
  const status = () => [
    ...state.nodes.map((n) => ({ source: 'neighbors', source_id: null, node_id: n.peer.id, last_poll: iso(now - 60000), error: null, entries: 14 })),
    ...v.sources.map((s) => ({ source: s.type, source_id: s.id, node_id: state.selfId, last_poll: iso(now - 120000), error: null, entries: 37 })),
  ]
  const answer = () => ({
    sources: v.sources.map(publicSource),
    prefixes: v.prefixes,
    effective_prefixes: [{ prefix: '2001:db8::/64', from: 'reverse_zone' }, ...v.prefixes.map((p) => ({ prefix: p, from: 'setting' }))],
    settings: { ...state.settings.ipv6 },
    status: status(),
  })
  const check = (s, field) => {
    if (!SOURCE_TYPES.includes(s.type)) throw invalid(`${field}.type`, `one of ${SOURCE_TYPES.join(', ')}`)
    if (!/^https:\/\/[^\s/]+(\/\S*)?$/.test(s.url || '')) throw invalid(`${field}.url`, 'https URL expected')
    if (!s.name || !String(s.name).trim()) throw invalid(`${field}.name`, 'required')
  }

  return {
    'GET /hosts/ipv6': ({ query }) => {
      const filter = query.get('filter')
      if (filter && !FILTERS.includes(filter)) throw invalid('filter', `one of ${FILTERS.join(', ')}`)
      let items = v.hosts
      if (filter === 'missing_aaaa') items = items.filter((h) => h.observed.some((o) => ['eui64', 'stable'].includes(o.class) && !h.aaaa.includes(o.address)))
      if (filter === 'missing_ptr') items = items.filter((h) => h.aaaa.length > h.ptr.length)
      if (filter === 'stale') items = items.filter((h) => h.aaaa.some((a) => !h.observed.some((o) => o.address === a)))
      if (filter === 'unknown') items = items.filter((h) => !h.name)
      if (filter === 'random_mac') items = items.filter((h) => h.mac_random)
      if (query.get('zone')) items = items.filter((h) => h.proposal?.zone === query.get('zone') || h.name?.endsWith(query.get('zone')))
      return { ...paginate(items, query), meta: { unavailable: [] } }
    },
    'GET /admin/ipv6': () => answer(),
    'PUT /admin/ipv6': ({ body, user }) => {
      if ('prefixes' in body) {
        if (!Array.isArray(body.prefixes)) throw invalid('prefixes', 'list of IPv6 prefixes expected')
        const bad = body.prefixes.find((p) => !PREFIX_RE.test(p) || Number(p.split('/')[1]) > 128)
        if (bad) throw invalid('prefixes', `not an IPv6 prefix: ${bad}`)
        v.prefixes = [...body.prefixes]
      }
      if ('sources' in body) {
        const next = body.sources.map((s, i) => {
          check(s, `sources[${i}]`)
          const old = v.sources.find((x) => x.id === s.id)
          return { id: s.id || ulid(), type: s.type, name: s.name, url: s.url, verify_tls: s.verify_tls ?? true, ca_pem: s.ca_pem ?? null, enabled: s.enabled ?? true, secrets: { ...(old?.secrets || {}) } }
        })
        v.sources = next
      }
      for (const [id, secrets] of Object.entries(body.secrets || {})) {
        const s = v.sources.find((x) => x.id === id)
        if (!s) throw invalid(`secrets.${id}`, 'unknown source')
        for (const [k, val] of Object.entries(secrets)) {
          if (!SOURCE_SECRETS.includes(k)) throw invalid(`secrets.${id}.${k}`, 'unknown secret')
          if (val === null) delete s.secrets[k]
          else s.secrets[k] = val
        }
      }
      auditEntry(state, user, { action: 'admin.ipv6.replace', target: 'ipv6', request: { sources: v.sources.map((s) => s.id), prefixes: v.prefixes } })
      return answer()
    },
    'POST /admin/ipv6/sources/test': ({ body }) => {
      const s = body.source_id ? v.sources.find((x) => x.id === body.source_id) : body
      if (!s) throw new Problem(404, 'not_found', `source ${body.source_id} not found`)
      if (!body.source_id) check(s, 'source')
      return { ok: true, node_id: state.selfId, entries: 37, sample: [{ mac: '02:00:5e:00:53:10', address: '2001:db8::5eff:fe00:5310', state: 'reachable' }] }
    },
  }
}
