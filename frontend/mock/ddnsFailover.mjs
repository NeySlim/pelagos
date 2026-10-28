// SPDX-License-Identifier: Apache-2.0
// DDNS failover of the mock (architecture section 24), shaped like services/ddns_failover.py and
// services/ddns_replay.py: the active primary of each dynamic zone with its blockers, the D2
// server lists, the outage window, the replay candidates, and the prepare, failover, switchover
// and replay plans. ddnsFailoverEvents() moves the state like the collectors do (outage, return
// of the old primary, its demotion) for /_mock/events.
import { iso } from './data.mjs'
import { setting } from './settings.mjs'

const UNSIGNED = new Set([null, undefined, '', 'none', 'insecure'])
const HOUR = 3600000

// Mock-only state: ddns.roles (cluster.toml), the D2 outage windows, the leases still lacking
// their records, the nodes still serving a zone given away. One zone denies transfers to the
// read key so the screen shows that blocker.
export function ddnsState(state) {
  state.ddnsFailover ||= {
    roles: {},
    noTransfer: new Set(['internal/100.51.198.in-addr.arpa.']),
    down: null, // {node, since, cause}: the active primary receives no update
    window: { open: null, last: null }, // epoch ms
    candidates: [],
    stale: {}, // "<view>/<zone>" -> node id still serving it as primary
  }
  return state.ddnsFailover
}

const keyOf = (z) => `${z.view || '_default'}/${z.name}`
const msg = (key, params = {}) => ({ key, params })
const isReverse = (name) => name.endsWith('in-addr.arpa.') || name.endsWith('ip6.arpa.')

export function ddnsFailoverModel(state) {
  const fo = ddnsState(state)
  const nodes = () => state.nodes.map((n) => n.peer)
  const nameOf = (id) => nodes().find((n) => n.id === id)?.name || id
  const bindNodes = () => nodes().filter((n) => n.modules?.bind !== false)
  const address = (id) => `192.0.2.${11 + state.nodes.findIndex((n) => n.peer.id === id)}`
  const offline = () => state.nodes.filter((n) => n.status !== 'online' && n.peer.modules?.bind !== false).map((n) => n.peer.id)
  const zones = () => state.zones.filter((z) => z.kind === 'primary' && z.dynamic)
  const primaryOf = (key) => fo.roles[key]?.primary || state.selfId

  function assess() {
    const many = bindNodes().length >= 2
    return zones().map((z) => {
      const key = keyOf(z)
      const role = fo.roles[key] || null
      const primary = primaryOf(key)
      const copies = bindNodes().map((n) => n.id).filter((id) => id !== primary)
      const hard = []
      if (!many) hard.push(msg('ddns.blocker.single_node'))
      if (z.source !== 'pelagos') hard.push(msg('ddns.blocker.not_managed', { zone: z.name, node: nameOf(primary) }))
      if (!UNSIGNED.has(z.dnssec_policy)) hard.push(msg('ddns.blocker.signed', { zone: z.name }))
      if (many && !copies.length) hard.push(msg('ddns.blocker.no_copy', { zone: z.name }))
      if (fo.noTransfer.has(key)) hard.push(msg('ddns.blocker.no_transfer', { zone: z.name, node: nameOf(copies[0] || primary), key: 'ddi-read' }))
      const blockers = hard.length ? hard : role ? [] : [msg('ddns.blocker.not_prepared')]
      return {
        key, zone: z.name, view: z.view || '_default', primary, copies, role, hard: hard.length > 0, blockers,
        stale: fo.stale[key] ? [fo.stale[key]] : [],
      }
    })
  }

  // Each D2 lists the primary, then the copies once the zone is prepared.
  function d2Lists(states) {
    const down = new Set(offline())
    return nodes().filter((n) => n.modules?.d2 !== false && !down.has(n.id)).map((n) => ({
      node_id: n.id,
      domains: states.map((st) => ({
        direction: isReverse(st.zone) ? 'reverse' : 'forward',
        name: st.zone,
        zone: st.key,
        servers: (st.role ? [st.primary, ...st.copies] : [st.primary]).map((id) => ({
          address: address(id), port: 53, node_id: id, role: id === st.primary ? 'primary' : 'secondary',
        })),
      })),
    }))
  }

  // ddns_replay.window(): the requested window, else the open outage, else the last closed one
  // inside replay_window_max_hours, else the last replay_window_max_hours.
  function window(body = {}) {
    const span = Number(setting(state, 'ddns.replay_window_max_hours') || 72) * HOUR
    const now = Date.now()
    const when = (v, field) => {
      if (v === undefined || v === null || v === '') return null
      const t = Date.parse(v)
      if (Number.isNaN(t)) throw Object.assign(new Error(`${field} is not a date`), { field })
      return t
    }
    let start = when(body.from, 'from')
    let end = when(body.to, 'to')
    let source
    if (start !== null || end !== null) {
      end ??= now
      start ??= end - span
      source = 'request'
    } else if (fo.window.open) {
      ;[start, end, source] = [fo.window.open, now, 'open']
    } else if (fo.window.last && fo.window.last.to >= now - span) {
      ;[start, end, source] = [fo.window.last.from, fo.window.last.to, 'outage']
    } else {
      ;[start, end, source] = [now - span, now, 'default']
    }
    if (source !== 'request') start = Math.max(start, end - span)
    return { start, end, source, span }
  }

  const candidates = (win) => {
    if (win.source === 'default' && !fo.candidates.length) return []
    return fo.candidates.filter((c) => c.at >= win.start && c.at <= win.end)
  }

  function resilience() {
    const states = assess()
    const win = window()
    return {
      zones: states.map((st) => ({
        zone: st.zone, view: st.view, primary_node_id: st.primary,
        epoch: st.role?.epoch || 0, since: st.role?.since || null, prepared_at: st.role?.prepared_at || null,
        copies: st.copies, ready: st.blockers.length === 0, blockers: st.blockers, stale: st.stale,
      })),
      d2: d2Lists(states),
      offline: offline(),
      outage: fo.window.open ? { since: iso(fo.window.open), zones: states.map((s) => s.key) } : null,
      replay: { from: iso(win.start), to: iso(win.end), source: win.source, candidates: candidates(win).length, notes: [] },
    }
  }

  return { fo, nodes, nameOf, address, offline, assess, d2Lists, window, candidates, resilience, primaryOf }
}

export function ddnsFailoverHandlers(state, { Problem, invalid, createPlan, hasPermission }) {
  const model = () => ddnsFailoverModel(state)
  const needBoth = (user, perms) => {
    const missing = perms.find((p) => !hasPermission(user, p))
    if (missing) throw new Problem(403, 'forbidden', `requires ${missing}`)
  }
  const pick = (states, zones, accept) => {
    if (zones === undefined || zones === null) return null
    if (!Array.isArray(zones) || !zones.length || !zones.every((z) => typeof z === 'string')) throw invalid('zones', 'list')
    return zones.map((raw, i) => {
      const [view, name] = raw.includes('/') ? [raw.slice(0, raw.lastIndexOf('/')) || '_default', raw.slice(raw.lastIndexOf('/') + 1)] : ['_default', raw]
      const st = states.find((s) => s.key === `${view}/${name.endsWith('.') ? name : `${name}.`}`)
      const why = accept(st)
      if (why) throw new Problem(400, 'validation_error', `${raw} ${why}`, [{ field: `zones[${i}]`, message: why }])
      return st
    })
  }
  const header = (m, ids) => ids.map((id) => `# ${m.nameOf(id)}\n`).join('')

  // The prepared zones asked for, every prepared zone by default (_failover_zones).
  const preparedZones = (m, body) => {
    const states = m.assess()
    const prepared = states.filter((s) => s.role && s.role.primary === s.primary)
    const chosen = pick(states, body.zones, (st) => (st && prepared.includes(st) ? null : 'is not a prepared dynamic zone'))
    if (chosen) return chosen
    if (!prepared.length) throw new Problem(409, 'conflict', 'no zone is prepared for failover: prepare the DDNS failover first')
    return prepared
  }

  const target = (m, states, raw) => {
    let to = raw
    if (to !== undefined && to !== null) {
      if (!m.nodes().some((n) => n.id === to)) throw invalid('to_node_id', 'unknown')
      if (m.offline().includes(to)) throw new Problem(400, 'validation_error', `${m.nameOf(to)} does not answer: it cannot be promoted`, [{ field: 'to_node_id', message: 'offline' }])
    } else {
      to = m.nodes().map((n) => n.id).find((id) => !m.offline().includes(id) && states.every((st) => st.copies.includes(id)))
      if (!to) throw new Problem(400, 'validation_error', 'no node holds a copy of every selected zone: give to_node_id', [{ field: 'to_node_id', message: 'required' }])
    }
    for (const st of states) {
      if (st.primary === to) throw new Problem(400, 'validation_error', `${m.nameOf(to)} is already the active primary of ${st.zone}`, [{ field: 'to_node_id', message: 'already primary' }])
      if (!st.copies.includes(to)) throw new Problem(400, 'validation_error', `${m.nameOf(to)} holds no copy of ${st.zone}`, [{ field: 'to_node_id', message: 'no copy' }])
    }
    return to
  }

  const answers = (m, st) => !(m.fo.down && m.fo.down.node === st.primary)

  // Promotion parts shared by failover and switchover: the target's zone rewritten primary, D2
  // lists target first, ddns.roles at the next epoch.
  function roleChange(m, states, to, user, kind) {
    const olds = [...new Set(states.map((s) => s.primary))]
    const epoch = Math.max(...states.map((s) => (s.role?.epoch || 0) + 1))
    const changes = []
    let diff = ''
    if (kind === 'switchover') {
      for (const st of states) {
        changes.push({ op: 'replace', target: `op:freeze/${st.key}`, before: null, after: { op: 'freeze' }, node_ids: [st.primary] })
        diff += `${header(m, [st.primary])}+rndc freeze ${st.zone}\n`
      }
    }
    for (const st of states) {
      const promote = { from: st.primary, epoch: (st.role?.epoch || 0) + 1, ...(kind === 'switchover' ? { sync: { address: m.address(st.primary), port: 53 } } : {}) }
      changes.push({ op: 'replace', target: `zone/${st.key}`, before: { kind: 'secondary', primaries: [`${m.address(st.primary)} key ddi-read`] }, after: { kind: 'primary', file: `${st.zone}e${promote.epoch}.db`, update_policy: st.role.policy || [], promote }, node_ids: [to] })
      diff += `${header(m, [to])}-zone "${st.zone}" { type secondary; primaries { ${m.address(st.primary)} key ddi-read; }; };\n+zone "${st.zone}" { type primary; file "${st.zone}e${promote.epoch}.db"; update-policy { ${(st.role.policy || []).join('; ')}; }; };\n`
      if (kind === 'switchover') {
        changes.push({ op: 'replace', target: `zone/${st.key}`, before: { kind: 'primary' }, after: { kind: 'secondary', demote: { to, epoch: promote.epoch } }, node_ids: [st.primary] })
        diff += `${header(m, [st.primary])}-zone "${st.zone}" { type primary; };\n+zone "${st.zone}" { type secondary; primaries { ${m.address(to)} key ddi-read; }; };\n`
      }
    }
    for (const d2 of m.d2Lists(states)) {
      if (m.offline().includes(d2.node_id) || (kind === 'failover' && m.fo.down?.node === d2.node_id && m.fo.down.cause === 'peer_offline')) continue
      for (const dom of d2.domains) {
        const before = dom.servers.map((s) => s.address)
        const after = [m.address(to), ...before.filter((a) => a !== m.address(to))]
        changes.push({ op: 'replace', target: `${dom.direction}-ddns/${dom.name}/dns-servers`, before, after, node_ids: [d2.node_id] })
      }
      diff += `${header(m, [d2.node_id])}-dns-servers ${d2.domains[0]?.servers.map((s) => s.address).join(', ')}\n+dns-servers ${m.address(to)} first\n`
    }
    for (const st of states) {
      const after = { ...st.role, primary: to, epoch: (st.role?.epoch || 0) + 1, since: iso(Date.now()), by: user.username }
      changes.push({ op: 'replace', target: `ddns.roles/${st.key}`, before: st.role, after, node_ids: [state.selfId] })
      diff += `${header(m, [state.selfId])}~ddns.roles/${st.key} primary=${to} epoch=${after.epoch}\n`
    }
    const params = { node: m.nameOf(to), count: states.length, previous: olds.map(m.nameOf).join(', '), epoch, zones: states.map((s) => s.zone) }
    const key = kind === 'failover' ? 'plan.ddns.failover' : 'plan.ddns.switchover'
    const summary = kind === 'failover'
      ? `promote ${params.node} primary of ${params.count} zones in place of ${params.previous} (epoch ${epoch}): ${params.zones.join(', ')}`
      : `give the primary role of ${params.count} zones back to ${params.node} from ${params.previous} (epoch ${epoch}): ${params.zones.join(', ')}`
    const targets = [...new Set(changes.flatMap((c) => c.node_ids))]
    return createPlan(state, user, {
      scope: 'dns.failover',
      summary,
      summary_message: { key, params },
      changes,
      diff,
      targets,
      validations: targets.map((node_id) => ({ ok: true, tool: changes.some((c) => c.node_ids.includes(node_id) && c.target.includes('-ddns/')) && !changes.some((c) => c.node_ids.includes(node_id) && c.target.startsWith('zone/')) ? 'kea-dhcp-ddns -t' : 'named-checkconf', output: '', node_id })),
      requires_confirmation: true,
      apply: () => {
        const now = Date.now()
        for (const st of states) {
          m.fo.roles[st.key] = { ...st.role, primary: to, epoch: (st.role?.epoch || 0) + 1, since: iso(now), by: user.username }
          // A down primary still serves its zones as primary when it comes back.
          if (kind === 'failover') m.fo.stale[st.key] = st.primary
        }
        if (kind === 'failover' && m.fo.down) m.fo.down = { ...m.fo.down, promoted: true }
        resolveAlerts(state, (a) => a.kind === 'ddns_outage' && states.some((s) => a.subject === `ddns:${s.key}`))
        if (kind === 'failover' && m.fo.window.open) {
          m.fo.window = { open: null, last: { from: m.fo.window.open, to: now } }
        }
      },
      job: kind === 'failover' ? ['promote', 'repoint', 'd2-lists', 'roles'] : ['freeze', 'wait-serial', 'promote', 'demote', 'd2-lists', 'roles'],
    })
  }

  return {
    'GET /dhcp/ddns/resilience': ({ user }) => {
      needBoth(user, ['read:dhcp', 'read:dns'])
      return model().resilience()
    },

    'POST /dhcp/ddns/resilience/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const m = model()
      const off = m.offline()
      if (off.length) {
        throw new Problem(400, 'validation_error', `${m.nameOf(off[0])} does not answer: its zones and D2 lists cannot be checked; retry once it is back`, off.map((n) => ({ field: 'zones', message: n })))
      }
      const states = m.assess()
      let chosen = pick(states, body.zones, (st) => (!st ? 'is not a dynamic zone D2 updates' : st.hard ? `cannot be prepared: ${st.blockers.map((b) => b.key).join('; ')}` : null))
      if (!chosen) {
        chosen = states.filter((s) => !s.hard)
        if (!chosen.length) throw new Problem(409, 'conflict', 'no dynamic zone can be prepared')
      }
      const todo = chosen.filter((s) => !s.role)
      if (!todo.length) throw new Problem(409, 'conflict', 'every selected zone is already prepared')
      const now = iso(Date.now())
      const changes = []
      let diff = ''
      const copies = [...new Set(todo.flatMap((s) => s.copies))]
      for (const id of copies) {
        for (const k of ['kea-ddns', 'ddi-admin']) changes.push({ op: 'add', target: `key/${k}`, before: null, after: { name: k, algorithm: 'hmac-sha256', secret: '********' }, node_ids: [id] })
        diff += `${header(m, [id])}+key "kea-ddns" { algorithm hmac-sha256; secret "********"; };\n+key "ddi-admin" { algorithm hmac-sha256; secret "********"; };\n`
      }
      for (const d2 of m.d2Lists(todo)) {
        for (const dom of d2.domains) {
          const st = todo.find((s) => s.key === dom.zone)
          const after = [st.primary, ...st.copies].map((id) => m.address(id))
          changes.push({ op: 'replace', target: `${dom.direction}-ddns/${dom.name}/dns-servers`, before: dom.servers.map((s) => s.address), after, node_ids: [d2.node_id] })
          diff += `${header(m, [d2.node_id])} "name": "${dom.name}"\n${after.slice(1).map((a) => `+  { "ip-address": "${a}", "port": 53 }\n`).join('')}`
        }
      }
      const roles = {}
      for (const st of todo) {
        const z = state.zones.find((x) => keyOf(x) === st.key)
        roles[st.key] = { primary: st.primary, epoch: 1, since: now, by: user.username, policy: [...(z?.update_policy || [])], prepared_at: now }
        changes.push({ op: 'add', target: `ddns.roles/${st.key}`, before: null, after: roles[st.key], node_ids: [state.selfId] })
        diff += `${header(m, [state.selfId])}+ddns.roles/${st.key} primary=${st.primary} epoch=1\n`
      }
      const targets = [...new Set(changes.flatMap((c) => c.node_ids))]
      const zonesList = todo.map((s) => s.zone)
      return createPlan(state, user, {
        scope: 'dns.failover',
        summary: `prepare the DDNS failover of ${todo.length} zones: ${zonesList.join(', ')}`,
        summary_message: { key: 'plan.ddns.prepare', params: { count: todo.length, zones: zonesList } },
        changes,
        diff,
        targets,
        apply: () => Object.assign(m.fo.roles, roles),
        job: ['keys', 'd2-lists', 'roles'],
      })
    },

    'POST /dhcp/ddns/failover/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const m = model()
      const states = preparedZones(m, body)
      const to = target(m, states, body.to_node_id)
      const answering = states.find((st) => answers(m, st))
      if (answering) throw new Problem(409, 'conflict', `${m.nameOf(answering.primary)} still serves ${answering.zone}: use the planned switchover`)
      return roleChange(m, states, to, user, 'failover')
    },

    'POST /dhcp/ddns/switchover/plan': ({ body, user }) => {
      needBoth(user, ['write:dns.zones', 'write:dhcp.config'])
      const m = model()
      const states = preparedZones(m, body)
      const to = target(m, states, body.to_node_id)
      const silent = states.find((st) => m.offline().includes(st.primary) || !answers(m, st))
      if (silent) throw new Problem(409, 'conflict', `${m.nameOf(silent.primary)} does not serve ${silent.zone}: promote the copy with the failover plan instead`)
      return roleChange(m, states, to, user, 'switchover')
    },

    'POST /dhcp/ddns/replay/plan': ({ body, user }) => {
      const m = model()
      const family = body.family
      if (![undefined, null, '', 'v4', 'v6'].includes(family)) throw invalid('family', 'v4 or v6')
      if (body.limit !== undefined && (!Number.isInteger(body.limit) || body.limit < 1)) throw invalid('limit', 'positive integer')
      let win
      try {
        win = m.window(body)
      } catch (err) {
        throw invalid(err.field || 'from', err.message)
      }
      if (win.start >= win.end) throw invalid('from', 'before to')
      if (win.end - win.start > win.span) throw new Problem(400, 'validation_error', `the window is longer than ${win.span / HOUR} h (ddns.replay_window_max_hours)`, [{ field: 'from', message: `at most ${win.span / HOUR} h before to` }])
      const max = Number(setting(state, 'ddns.replay_max_leases') || 2000)
      const limit = Math.min(body.limit || max, max)
      const found = m.candidates(win).filter((c) => !family || c.family === family)
      if (!found.length) throw new Problem(409, 'conflict', `no lease active from ${iso(win.start)} to ${iso(win.end)} lacks its DNS records`)
      const chosen = found.slice(0, limit)
      const validations = [...new Set(chosen.map((c) => c.node_id))].map((node_id) => ({ ok: true, tool: 'lease_cmds', output: '', node_id }))
      if (found.length > limit) validations.push({ ok: true, tool: 'ddns.replay', output: `${found.length - limit} more leases qualify: replay again once this plan is applied`, output_message: { key: 'ddns.replay.more', params: { count: found.length - limit } }, node_id: state.selfId })
      const engines = [...new Set(chosen.map((c) => (c.family === 'v6' ? 'kea6' : 'kea4')))]
      const params = { count: chosen.length, start: iso(win.start), end: iso(win.end) }
      return createPlan(state, user, {
        scope: 'dhcp.lease',
        engine: engines.length === 1 ? engines[0] : null,
        summary: `resend the DNS updates of ${params.count} leases active from ${params.start} to ${params.end}`,
        summary_message: { key: 'plan.ddns.replay', params },
        changes: chosen.map((c) => ({
          op: 'replace', target: `resend/${c.ip}`,
          before: { records: c.missing.map((rtype) => ({ rtype, name: rtype === 'PTR' ? c.ptr : c.hostname, found: [] })) },
          after: { hostname: c.hostname, fqdn_fwd: true, fqdn_rev: true, cltt: iso(c.at) },
          node_ids: [c.node_id],
        })),
        targets: [...new Set(chosen.map((c) => c.node_id))],
        validations,
        requires_confirmation: true,
        apply: () => {
          const sent = new Set(chosen.map((c) => c.ip))
          m.fo.candidates = m.fo.candidates.filter((c) => !sent.has(c.ip))
          if (!m.fo.candidates.length) resolveAlerts(state, (a) => a.kind === 'ddns_replay')
        },
      })
    },
  }
}

function resolveAlerts(state, match) {
  for (const a of state.alerts.filter((x) => x.state !== 'resolved' && match(x))) {
    a.state = 'resolved'
    a.resolved_at = iso(Date.now())
    a.last_seen = a.resolved_at
    state.emit?.('alerts', 'resolved', a)
  }
}

// /_mock/events kinds: the active primary stops receiving updates (named stopped on this node,
// or the peer offline), the old primary comes back still serving its zones as primary, then the
// collector demotes it.
export function ddnsFailoverEvents(state, { emit, ulid }) {
  const raise = (alert) => {
    const open = state.alerts.find((a) => a.kind === alert.kind && a.subject === alert.subject && a.state !== 'resolved')
    if (open) return open
    const now = iso(Date.now())
    const full = { id: ulid(), state: 'open', engine: 'bind', first_seen: now, last_seen: now, acked_by: null, acked_at: null, resolved_at: null, reported_by: [state.selfId], ...alert }
    state.alerts.unshift(full)
    emit('alerts', 'opened', full)
    return full
  }
  return {
    'ddns-outage'({ node_id: nodeId, minutes = 12 } = {}) {
      const m = ddnsFailoverModel(state)
      const states = m.assess().filter((s) => s.role)
      const node = nodeId || (states[0] ? states[0].primary : state.selfId)
      const since = Date.now() - minutes * 60000
      const cause = node === state.selfId ? 'named_down' : 'peer_offline'
      m.fo.down = { node, since, cause }
      m.fo.window = { ...m.fo.window, open: since }
      if (cause === 'peer_offline') {
        const n = state.nodes.find((x) => x.peer.id === node)
        if (n) n.status = 'offline'
      }
      // Leases renewed during the outage: their names were never sent.
      const leases = (state.leases?.v4 || []).filter((l) => l.hostname && (!l.node_id || l.node_id === state.selfId)).slice(0, 3)
      m.fo.candidates = leases.map((l, i) => ({
        ip: l.ip_address, hostname: l.hostname.endsWith('.') ? l.hostname : `${l.hostname}.`, ptr: `${l.ip_address.split('.').reverse().join('.')}.in-addr.arpa.`,
        family: 'v4', node_id: state.nodes.find((x) => x.peer.id !== node)?.peer.id || state.selfId, at: since + (i + 1) * 60000, missing: ['A', 'PTR'],
      }))
      const ids = []
      for (const st of states.filter((s) => s.primary === node)) {
        const a = raise({
          kind: 'ddns_outage', severity: 'critical', node_id: node, subject: `ddns:${st.key}`,
          title: `zone ${st.zone}: the active primary ${m.nameOf(node)} has received no DDNS update since ${iso(since)}`,
          title_message: { key: 'alert.ddns_outage', params: { zone: st.zone, node: m.nameOf(node), since: iso(since) } },
          details: { zone: st.zone, view: st.view, primary_node_id: node, epoch: st.role.epoch, cause, since: iso(since), remediation: 'ddns_failover' },
          reported_by: state.nodes.map((x) => x.peer.id).filter((id) => id !== node || cause === 'named_down'),
        })
        ids.push(a.id)
      }
      return { ok: true, node_id: node, alerts: ids }
    },

    // The old primary is back: it still serves the zones handed over as primary (stale) until the
    // collector demotes it; the outage window closes and the replay alert opens.
    'ddns-return'() {
      const m = ddnsFailoverModel(state)
      const down = m.fo.down
      if (!down) return { ok: false }
      const n = state.nodes.find((x) => x.peer.id === down.node)
      if (n) n.status = 'online'
      const now = Date.now()
      if (m.fo.window.open) m.fo.window = { open: null, last: { from: m.fo.window.open, to: now } }
      m.fo.down = null
      resolveAlerts(state, (a) => a.kind === 'ddns_outage')
      const ids = []
      for (const [key, node] of Object.entries(m.fo.stale)) {
        const role = m.fo.roles[key]
        const zone = key.slice(key.indexOf('/') + 1)
        const a = raise({
          kind: 'dns_stale_primary', severity: 'critical', node_id: node, subject: `ddns:stale:${key}`,
          title: `zone ${zone} is served as primary on ${m.nameOf(node)} but the primary role belongs to ${m.nameOf(role.primary)} (epoch ${role.epoch})`,
          title_message: { key: 'alert.dns_stale_primary', params: { zone, node: m.nameOf(node), primary: m.nameOf(role.primary), epoch: role.epoch } },
          details: { zone, view: key.slice(0, key.indexOf('/')), primary_node_id: role.primary, epoch: role.epoch, local_epoch: role.epoch - 1, demotable: true },
          reported_by: [node],
        })
        ids.push(a.id)
      }
      if (m.fo.candidates.length) {
        const last = m.fo.window.last
        const params = { count: m.fo.candidates.length, start: iso(last.from), end: iso(last.to) }
        const a = raise({
          kind: 'ddns_replay', severity: 'warning', node_id: null, engine: null, subject: 'ddns:replay',
          title: `${params.count} leases of the DDNS outage from ${params.start} to ${params.end} lack their DNS records`,
          title_message: { key: 'alert.ddns_replay', params },
          details: { from: params.start, to: params.end, count: params.count, leases: m.fo.candidates.map((c) => c.ip) },
        })
        ids.push(a.id)
      }
      return { ok: true, node_id: down.node, alerts: ids }
    },

    'ddns-demote'() {
      const m = ddnsFailoverModel(state)
      const keys = Object.keys(m.fo.stale)
      m.fo.stale = {}
      resolveAlerts(state, (a) => a.kind === 'dns_stale_primary')
      return { ok: true, zones: keys }
    },
  }
}
