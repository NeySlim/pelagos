// SPDX-License-Identifier: Apache-2.0
// RPZ subscriptions for the mock server: the real catalog file, selections kept in memory, a plan per change.
import { readFileSync } from 'node:fs'

const CATALOG = JSON.parse(readFileSync(new URL('../../backend/pelagos/rpz/catalog.json', import.meta.url), 'utf8'))
const LEVELS = ['light', 'normal', 'strict']
const BYTES_PER_ENTRY = 800
const NODE_RAM = [8192, 4096, 2048]
const ZONE_SUFFIX = 'rpz.invalid'

const zoneOf = (id) => `${id.toLowerCase().replace(/[^a-z0-9-]/g, '-')}.${ZONE_SUFFIX}`

function levelLists(cat, level) {
  const levels = CATALOG.categories[cat].levels
  if (levels[level]) return levels[level]
  const have = LEVELS.filter((l) => levels[l])
  const want = LEVELS.indexOf(level)
  have.sort((a, b) => Math.abs(LEVELS.indexOf(a) - want) - Math.abs(LEVELS.indexOf(b) - want))
  return levels[have[0]]
}

function summary(cat) {
  return Object.fromEntries(
    Object.keys(CATALOG.categories[cat].levels).map((level) => {
      const lists = levelLists(cat, level)
      return [level, { lists, entries: lists.reduce((n, i) => n + CATALOG.lists[i].entries, 0) }]
    }),
  )
}

const catalogView = () => ({
  version: CATALOG.version,
  note: CATALOG.note,
  lists: CATALOG.lists,
  categories: Object.fromEntries(
    Object.entries(CATALOG.categories).map(([id, c]) => [id, { icon: c.icon, levels: summary(id), lists: c.lists, addons: c.addons || [] }]),
  ),
})

export function rpzState() {
  return {
    categories: {},
    subscriptions: {},
    order: [],
    allow: [],
    exempt_clients: [],
    applied: [],
    activity: {
      by_list: { 'oisd-small': 18342, 'hagezi-tif.mini': 211 },
      by_category: { ads: 18342, security: 211 },
      recent: [
        { time: '26-Oct-2026 10:41:02.114', client: '192.0.2.31', qname: 'ads.tracker.example.net', qtype: 'A', trigger: 'QNAME', action: 'NXDOMAIN', list: 'oisd-small', category: 'ads', rule: '*.tracker.example.net', node_id: 'ns1' },
        { time: '26-Oct-2026 10:40:58.002', client: '192.0.2.44', qname: 'phish.example.org', qtype: 'A', trigger: 'QNAME', action: 'NXDOMAIN', list: 'hagezi-tif.mini', category: 'security', rule: 'phish.example.org', node_id: 'ns1' },
      ],
    },
  }
}

function resolve(rpz) {
  const subs = {}
  for (const [cat, sel] of Object.entries(rpz.categories)) {
    const ids = sel.level === 'custom' ? sel.lists || [] : levelLists(cat, sel.level || 'normal')
    for (const id of [...ids, ...(sel.addons || [])]) {
      const item = CATALOG.lists[id]
      subs[id] = {
        id, name: item.name, kind: 'url', url: item.url, format: item.format, zone: zoneOf(id), enabled: sel.enabled,
        action: sel.action || 'nxdomain', redirect: sel.redirect || '', interval_hours: sel.interval_hours || 24, nodes: sel.nodes || null,
        category: cat, source: 'catalog', license: item.license, homepage: item.homepage || '', entries_hint: item.entries, primaries: [], tsig_key: '', note: item.note || '',
      }
    }
    for (const extra of sel.urls || []) {
      const id = `${cat}-u${Buffer.from(extra.url).toString('hex').slice(0, 6)}`
      subs[id] = {
        id, name: extra.name || extra.url, kind: 'url', url: extra.url, format: extra.format || 'auto', zone: zoneOf(id), enabled: sel.enabled,
        action: sel.action || 'nxdomain', redirect: sel.redirect || '', interval_hours: sel.interval_hours || 24, nodes: sel.nodes || null,
        category: cat, source: 'category_url', license: '', homepage: '', entries_hint: 0, primaries: [], tsig_key: '', note: '',
      }
    }
  }
  for (const [id, sub] of Object.entries(rpz.subscriptions)) {
    subs[id] = {
      id, name: sub.name || id, kind: sub.kind || 'url', url: sub.url || '', format: sub.format || 'auto', zone: sub.zone || zoneOf(id),
      enabled: sub.enabled !== false, action: sub.action || 'nxdomain', redirect: sub.redirect || '', interval_hours: sub.interval_hours || 24,
      nodes: sub.nodes || null, category: sub.category || null, source: 'custom', license: '', homepage: '', entries_hint: 0,
      primaries: sub.primaries || [], tsig_key: sub.tsig_key || '', note: sub.note || '',
    }
  }
  const order = rpz.order.filter((i) => subs[i])
  return [...order, ...Object.keys(subs).filter((i) => !order.includes(i))].map((i) => subs[i])
}

const wantedZones = (rpz) => resolve(rpz).filter((s) => s.enabled).map((s) => s.zone)

function statusOf(sub, now) {
  const entries = sub.entries_hint || 4200
  return {
    status: 'ok', error: '', entries, bytes: entries * 62, format: sub.format === 'auto' ? 'domains' : sub.format,
    updated_at: Math.floor(now / 1000) - 5 * 3600, ok_at: Math.floor(now / 1000) - 300, checked_at: Math.floor(now / 1000) - 300,
    source_date: Math.floor(now / 1000) - 9 * 3600, next_check: Math.floor(now / 1000) + 19 * 3600, failures: 0,
  }
}

export function rpzHandlers(state, { createPlan, invalid, notFound }) {
  const rpz = (state.rpz ||= rpzState())
  const nodes = () => state.nodes.map((n, i) => ({ id: n.peer.id, name: n.peer.name, ram_mb: NODE_RAM[i] ?? 8192 }))

  const overview = () => {
    const subs = resolve(rpz)
    const now = Date.now()
    const wanted = wantedZones(rpz)
    const pending = wanted.length ? JSON.stringify([...wanted].sort()) !== JSON.stringify([...rpz.applied].sort()) : rpz.applied.length > 0
    return {
      catalog: catalogView(),
      categories: rpz.categories,
      subscriptions: subs.map((s) => ({
        ...s,
        status: Object.fromEntries(nodes().filter((n) => !s.nodes || s.nodes.includes(n.id)).map((n) => [n.id, rpz.applied.includes(s.zone) ? statusOf(s, now) : null])),
      })),
      order: subs.map((s) => s.id),
      allow: rpz.allow,
      exempt_clients: rpz.exempt_clients,
      nodes: nodes().map((n) => ({ ...n, error: null, pending, log: '/var/cache/bind/pelagos/rpz/rpz.log' })),
      settings: { check_seconds: 300, default_interval_hours: 24, shrink_percent: 50, bytes_per_entry: BYTES_PER_ENTRY, memory_warn_percent: 25, small_node_mb: 4096, break_dnssec: true },
      allow_zone: `pelagos-allow.${ZONE_SUFFIX}`,
    }
  }

  const planNow = (user) => {
    const wanted = wantedZones(rpz)
    const before = [...rpz.applied]
    if (JSON.stringify([...wanted].sort()) === JSON.stringify([...before].sort())) return null
    const text = (zones) => zones.map((z) => `zone "${z}" { type primary; };`).join('\n')
    return createPlan(state, user, {
      scope: 'dns.config', engine: 'bind', tool: 'named-checkconf',
      summary: `RPZ subscriptions: ${wanted.length} policy zones`,
      changes: [{ op: 'replace', target: 'rpz/state', before: { zones: before }, after: { zones: wanted }, node_ids: [] }],
      diff: `--- zones.conf\n+++ zones.conf\n${before.map((z) => `-zone "${z}" { type primary; };`).join('\n')}\n${text(wanted).split('\n').map((l) => `+${l}`).join('\n')}\n`,
      targets: state.nodes.map((n) => n.peer.id),
      requires_confirmation: before.some((z) => !wanted.includes(z)),
      apply: () => { rpz.applied = wanted },
      rollback: () => { rpz.applied = before },
    })
  }
  const result = (user) => ({ plan: planNow(user), overview: overview() })

  const checkAction = (body) => {
    if (body.action && !['nxdomain', 'nodata', 'redirect', 'passthru'].includes(body.action)) throw invalid('action', 'nxdomain, nodata, redirect or passthru')
    if (body.action === 'redirect' && !body.redirect) throw invalid('redirect', 'an IP address or a host name')
  }

  return {
    'GET /dns/rpz/overview': () => overview(),
    'GET /dns/rpz/catalog': () => catalogView(),
    'PUT /dns/rpz/categories/{category}': ({ params, body, user }) => {
      if (!CATALOG.categories[params.category]) throw invalid('category', 'unknown category')
      if (body.level && ![...LEVELS, 'custom'].includes(body.level)) throw invalid('level', 'light, normal, strict or custom')
      checkAction(body)
      rpz.categories[params.category] = { enabled: body.enabled !== false, level: body.level || 'normal', addons: body.addons || [], urls: body.urls || [], lists: body.lists || [], action: body.action || 'nxdomain', redirect: body.redirect || '', interval_hours: body.interval_hours || 24, nodes: body.nodes || null }
      return result(user)
    },
    'DELETE /dns/rpz/categories/{category}': ({ params, user }) => {
      if (!CATALOG.categories[params.category]) throw notFound(`category ${params.category}`)
      delete rpz.categories[params.category]
      return result(user)
    },
    'PUT /dns/rpz/subscriptions/{id}': ({ params, body, user }) => {
      checkAction(body)
      if (body.kind === 'axfr' && !body.primaries?.length) throw invalid('primaries', 'at least one primary')
      if (body.kind !== 'axfr' && !/^https?:\/\//.test(body.url || '')) throw invalid('url', 'an http or https address')
      rpz.subscriptions[params.id] = { ...body, tsig_secret: undefined }
      return result(user)
    },
    'DELETE /dns/rpz/subscriptions/{id}': ({ params, user }) => {
      if (!rpz.subscriptions[params.id]) throw notFound(`subscription ${params.id}`)
      delete rpz.subscriptions[params.id]
      return result(user)
    },
    'PUT /dns/rpz/order': ({ body, user }) => {
      rpz.order = body.order || []
      return result(user)
    },
    'POST /dns/rpz/plan': ({ user }) => result(user),
    'POST /dns/rpz/estimate': ({ body }) => {
      const lists = body.category
        ? [...(body.level === 'custom' ? body.lists || [] : levelLists(body.category, body.level || 'normal')), ...(body.addons || [])]
        : body.lists || []
      const entries = lists.reduce((n, i) => n + (CATALOG.lists[i]?.entries || 0), 0)
      const current = resolve(rpz).filter((s) => s.enabled && !lists.includes(s.id)).map((s) => s.entries_hint)
      return {
        lists, entries, memory_mb: Math.round((entries * BYTES_PER_ENTRY) / 1e5) / 10,
        nodes: nodes().map((n) => {
          const all = [...current, ...lists.map((i) => CATALOG.lists[i]?.entries || 0)]
          const total = all.reduce((a, b) => a + b, 0)
          const peak = ((total + Math.max(0, ...all)) * BYTES_PER_ENTRY) / 1e6
          const percent = Math.round((peak * 1000) / n.ram_mb) / 10
          const level = percent >= 25 ? 'high' : n.ram_mb <= 4096 && percent >= 12.5 ? 'caution' : 'ok'
          return { node_id: n.id, name: n.name, entries: total, memory_mb: Math.round((total * BYTES_PER_ENTRY) / 1e5) / 10, peak_mb: Math.round(peak * 10) / 10, ram_mb: n.ram_mb, percent_of_ram: percent, level }
        }),
      }
    },
    'POST /dns/rpz/refresh': () => ({ requested: true }),
    'GET /dns/rpz/why': ({ query }) => {
      const domain = (query.get('domain') || '').toLowerCase()
      if (!domain) throw invalid('domain', 'required')
      const allowed = rpz.allow.find((a) => domain === a.domain || domain.endsWith(`.${a.domain}`))
      const matches = []
      if (allowed) matches.push({ zone: `pelagos-allow.${ZONE_SUFFIX}`, list: 'allow', name: 'allow', category: null, rule: allowed.domain, match: 'exact', passthru: true, action: 'passthru', applied: true })
      const hit = resolve(rpz).find((s) => s.enabled && /(^|\.)(ads|tracker|phish)\./.test(domain))
      if (hit) matches.push({ zone: hit.zone, list: hit.id, name: hit.name, category: hit.category, rule: `*.${domain.split('.').slice(1).join('.')}`, match: 'wildcard', passthru: hit.action === 'passthru', action: hit.action, applied: matches.length === 0 })
      const verdict = !matches.length ? 'not_listed' : matches[0].passthru ? 'allowed' : 'blocked'
      return { domain, verdict, matches }
    },
    'GET /dns/rpz/activity': () => {
      const subs = Object.fromEntries(resolve(rpz).map((s) => [s.id, s]))
      return {
        nodes: nodes().map((n) => ({ id: n.id, name: n.name, log: '/var/cache/bind/pelagos/rpz/rpz.log', since: 1792900000 })),
        by_list: Object.entries(rpz.activity.by_list).map(([list, hits]) => ({ list, name: subs[list]?.name || CATALOG.lists[list]?.name || list, category: subs[list]?.category || null, hits })),
        by_category: Object.entries(rpz.activity.by_category).map(([category, hits]) => ({ category, hits })),
        recent: rpz.activity.recent,
      }
    },
    'POST /dns/rpz/allow': ({ body, user }) => {
      const domain = String(body.domain || '').trim().toLowerCase().replace(/\.$/, '').replace(/^\*\./, '')
      if (!/^([a-z0-9_-]+\.)*[a-z0-9_-]+$/.test(domain)) throw invalid('domain', 'not a valid name')
      rpz.allow = [...rpz.allow.filter((a) => a.domain !== domain), { domain, note: body.note || '', by: user.username, at: new Date().toISOString() }]
      return { applied_here: true, allow: rpz.allow, exempt_clients: rpz.exempt_clients }
    },
    'DELETE /dns/rpz/allow': ({ query }) => {
      const domain = query.get('domain')
      if (!rpz.allow.some((a) => a.domain === domain)) throw notFound(`allowed domain ${domain}`)
      rpz.allow = rpz.allow.filter((a) => a.domain !== domain)
      return { applied_here: true, allow: rpz.allow, exempt_clients: rpz.exempt_clients }
    },
    'POST /dns/rpz/exempt': ({ body, user }) => {
      if (!/^[0-9a-f.:]+(\/\d+)?$/i.test(body.cidr || '')) throw invalid('cidr', 'not an address or network')
      const cidr = body.cidr.includes('/') ? body.cidr : `${body.cidr}/${body.cidr.includes(':') ? 128 : 32}`
      rpz.exempt_clients = [...rpz.exempt_clients.filter((c) => c.cidr !== cidr), { cidr, note: body.note || '', by: user.username, at: new Date().toISOString() }]
      return { applied_here: true, allow: rpz.allow, exempt_clients: rpz.exempt_clients }
    },
    'DELETE /dns/rpz/exempt': ({ query }) => {
      const cidr = query.get('cidr')
      if (!rpz.exempt_clients.some((c) => c.cidr === cidr)) throw notFound(`exempt client ${cidr}`)
      rpz.exempt_clients = rpz.exempt_clients.filter((c) => c.cidr !== cidr)
      return { applied_here: true, allow: rpz.allow, exempt_clients: rpz.exempt_clients }
    },
  }
}
