// SPDX-License-Identifier: Apache-2.0
// Outgoing notifications of the mock (architecture section 22): channels with secrets as
// booleans, sender order, mute, a history of sent batches. Nothing leaves the process.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

export const CHANNEL_TYPES = ['email', 'ntfy', 'gotify', 'matrix', 'webhook', 'home_assistant']
// Secret names per type (cluster.toml [secrets] "notify/<id>/<name>").
export const CHANNEL_SECRETS = {
  email: ['password'], ntfy: ['token', 'password'], gotify: ['token'], matrix: ['token'],
  webhook: ['hmac_secret'], home_assistant: ['webhook_id'],
}
const DEFAULT_FILTERS = { severity_min: 'warning', kinds_include: [], kinds_exclude: ['ha_transition'], node_ids: [], engines: [] }
const DEFAULT_SCHEDULE = { reminder_hours: 12, send_resolved: true, confirm_seconds: null, quiet: null }

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

const TEST_LIMIT_PER_MINUTE = 6
// Mock only: a channel whose URL or SMTP host names this host fails every send.
export const UNREACHABLE_HOST = 'unreachable.example.lan'

// The notifications state of the mock, created on first use (and again after a scenario switch).
export function notifyState(state) {
  const now = Date.now()
  state.notify ||= {
    channels: [
      {
        id: 'ch-ntfy', type: 'ntfy', name: 'Phone (ntfy)', enabled: true, language: 'en',
        params: { url: 'https://ntfy.example.lan', topic: 'pelagos' },
        filters: { ...DEFAULT_FILTERS }, schedule: { ...DEFAULT_SCHEDULE },
        secrets: { token: 'tk_mock' }, status: { state: 'ok', since: iso(now - 86400000), last_sent_at: iso(now - 3600000), last_error: null },
      },
    ],
    order: null,
    mute: null,
    history: [
      {
        id: ulid(now - 3600000), ts: iso(now - 3600000), channel_id: 'ch-ntfy', channel_name: 'Phone (ntfy)', node_id: state.selfId,
        batch_id: ulid(now - 3600000), reason: 'events', alert_ids: ['A1'],
        events: [{ event: 'opened', alert_id: 'A1', kind: 'ha_partner_down', severity: 'critical', first_seen: iso(now - 3700000) }],
        result: 'ok', status: 200, duration_ms: 87, error: null,
      },
      // The critical rndc key alert of the mock data went out through ntfy too.
      {
        id: ulid(now - 3500000), ts: iso(now - 3500000), channel_id: 'ch-ntfy', channel_name: 'Phone (ntfy)', node_id: state.selfId,
        batch_id: ulid(now - 3500000), reason: 'events', alert_ids: ['ALRT0000000000000000000005'],
        events: [{ event: 'opened', alert_id: 'ALRT0000000000000000000005', kind: 'insecure_key', severity: 'critical', first_seen: iso(now - 7200000) }],
        result: 'ok', status: 200, duration_ms: 64, error: null,
      },
    ].sort((a, b) => b.ts.localeCompare(a.ts)),
    tests: {},
  }
  return state.notify
}

export function notifyHandlers(state, { Problem, invalid }) {
  const now = Date.now()
  const order = () => notifyState(state).order || state.nodes.map((node) => node.peer.id)
  // Same targets as the server: a stored secret never follows a channel to another server.
  const TARGET = { email: 'host', matrix: 'homeserver' }
  const targetKey = (c) => TARGET[c.type] || 'url'
  const targetOf = (c) => String(c.params?.[targetKey(c)] || '').trim().replace(/\/+$/, '').toLowerCase()
  const warningsOf = (c) => {
    const url = c.params?.[targetKey(c)]
    const hasSecret = Object.values(c.secrets || {}).some(Boolean)
    return typeof url === 'string' && url.startsWith('http://') && hasSecret
      ? [{ field: `params.${targetKey(c)}`, message: 'plain http carries the secret unencrypted' }]
      : []
  }
  const dropNull = (o) => Object.fromEntries(Object.entries(o || {}).filter(([, v]) => v !== null && v !== undefined))
  const publicChannel = (c) => ({
    ...c,
    secrets: Object.fromEntries((CHANNEL_SECRETS[c.type] || []).map((k) => [k, Boolean(c.secrets?.[k])])),
    warnings: warningsOf(c),
  })
  const publicHistory = ({ alert_ids: _ids, ...h }) => h
  const channelOf = (id) => {
    const c = notifyState(state).channels.find((x) => x.id === id)
    if (!c) throw new Problem(404, 'not_found', `channel ${id} not found`)
    return c
  }
  const applySecrets = (c, secrets = {}) => {
    c.secrets ||= {}
    for (const [k, v] of Object.entries(secrets)) {
      if (!(CHANNEL_SECRETS[c.type] || []).includes(k)) throw invalid(`secrets.${k}`, 'unknown secret for this channel type')
      if (v === null) delete c.secrets[k]
      else c.secrets[k] = v
    }
  }
  const check = (c) => {
    if (!CHANNEL_TYPES.includes(c.type)) throw invalid('type', `one of ${CHANNEL_TYPES.join(', ')}`)
    if (!c.name || !String(c.name).trim()) throw invalid('name', 'required')
    if (!['en', 'fr'].includes(c.language)) throw invalid('language', 'en or fr')
  }

  return {
    'GET /admin/notifications': () => {
      const n = notifyState(state)
      return {
        channels: n.channels.map(publicChannel),
        settings: { ...state.settings.notifications },
        sender: { node_id: order()[0], since: iso(now - 86400000), order: order() },
        mute: n.mute,
        queue: { pending: 0, failing: n.channels.filter((c) => c.status.state === 'failing').length, node_id: order()[0] },
      }
    },
    'POST /admin/notifications/channels': ({ body, user, res }) => {
      const c = {
        id: ulid(), type: body.type, name: body.name, enabled: body.enabled ?? true, language: body.language || 'en',
        params: dropNull(body.params), filters: { ...DEFAULT_FILTERS, ...(body.filters || {}) },
        schedule: { ...DEFAULT_SCHEDULE, ...(body.schedule || {}) }, secrets: {},
        status: { state: 'ok', since: iso(Date.now()), last_sent_at: null, last_error: null },
      }
      check(c)
      applySecrets(c, body.secrets)
      notifyState(state).channels.push(c)
      auditEntry(state, user, { action: 'admin.notify.add', target: `notify:${c.id}`, request: { type: c.type, name: c.name } })
      res.statusCode = 201
      return publicChannel(c)
    },
    'PUT /admin/notifications/channels/{id}': ({ params, body, user }) => {
      const c = channelOf(params.id)
      if ('type' in body && body.type !== c.type) throw invalid('type', 'a channel keeps its type: create a new one')
      const next = { ...c, secrets: { ...c.secrets } }
      for (const k of ['name', 'enabled', 'language']) if (k in body) next[k] = body[k]
      if ('params' in body) next.params = dropNull(body.params)
      for (const k of ['filters', 'schedule']) if (k in body) next[k] = { ...c[k], ...body[k] }
      check(next)
      if (targetOf(next) !== targetOf(c)) {
        const kept = Object.keys(c.secrets || {}).filter((k) => c.secrets[k] && !(k in (body.secrets || {})))
        if (kept.length) throw invalid(`secrets.${kept[0]}`, 'enter it again or clear it: the server changed')
      }
      applySecrets(next, body.secrets)
      if (!next.enabled) next.status = { ...next.status, state: 'disabled' }
      else if (next.status.state === 'disabled') next.status = { ...next.status, state: 'ok' }
      Object.assign(c, next)
      auditEntry(state, user, { action: 'admin.notify.replace', target: `notify:${c.id}` })
      return publicChannel(c)
    },
    'DELETE /admin/notifications/channels/{id}': ({ params, user }) => {
      channelOf(params.id)
      const n = notifyState(state)
      n.channels = n.channels.filter((c) => c.id !== params.id)
      auditEntry(state, user, { action: 'admin.notify.delete', target: `notify:${params.id}` })
      return null
    },
    // A real send on the server, audited as admin.notify.op (op test), never in the history.
    // Mock only: a channel pointing at UNREACHABLE_HOST fails (200 with ok false, like the API).
    'POST /admin/notifications/test': ({ body, user, res }) => {
      const n = notifyState(state)
      const started = Date.now()
      const recent = (n.tests[user.username] || []).filter((ts) => started - ts < 60000)
      if (recent.length >= TEST_LIMIT_PER_MINUTE) {
        res.setHeader('Retry-After', String(Math.ceil((recent[0] + 60000 - started) / 1000)))
        throw new Problem(429, 'rate_limited', 'at most 6 test sends per minute')
      }
      n.tests[user.username] = [...recent, started]
      const c = body.channel_id ? channelOf(body.channel_id) : body
      if (!body.channel_id) {
        check({ language: 'en', name: 'test', ...c })
        // `scope` lends its stored secrets only to the same type and target server (as the API).
        if (body.scope) channelOf(body.scope)
      }
      auditEntry(state, user, { action: 'admin.notify.op', target: `notify:${body.channel_id || body.scope || 'test'}`, request: { op: 'test', type: c.type } })
      if (String(c.params?.[targetKey(c)] || '').includes(UNREACHABLE_HOST)) {
        return { ok: false, node_id: state.selfId, duration_ms: 15000, error: `connection failed: timed out (${UNREACHABLE_HOST})` }
      }
      return { ok: true, node_id: state.selfId, duration_ms: 42, status: 200 }
    },
    'PUT /admin/notifications/order': ({ body, user }) => {
      const ids = state.nodes.map((node) => node.peer.id)
      const list = body.node_ids || []
      if (list.length !== ids.length || !ids.every((id) => list.includes(id))) throw invalid('node_ids', 'every node exactly once')
      const n = notifyState(state)
      n.order = [...list]
      auditEntry(state, user, { action: 'admin.notify.op', target: 'notify:order', request: { op: 'order', node_ids: list } })
      return { order: n.order }
    },
    'PUT /admin/notifications/mute': ({ body, user }) => {
      const until = Date.parse(body.until || '')
      if (!Number.isFinite(until) || until <= Date.now()) throw invalid('until', 'a time in the future')
      if (until - Date.now() > 24 * 3600000) throw invalid('until', 'at most 24 hours ahead')
      if (!body.comment || !String(body.comment).trim()) throw invalid('comment', 'required')
      const n = notifyState(state)
      n.mute = { until: iso(until), comment: body.comment, by: user.username, at: iso(Date.now()) }
      auditEntry(state, user, { action: 'admin.notify.op', target: 'notify:mute', request: { op: 'mute', until: n.mute.until } })
      return { mute: n.mute }
    },
    'DELETE /admin/notifications/mute': ({ user }) => {
      notifyState(state).mute = null
      auditEntry(state, user, { action: 'admin.notify.op', target: 'notify:mute', request: { op: 'unmute' } })
      return null
    },
    'GET /admin/notifications/history': ({ query }) => {
      let items = notifyState(state).history
      if (query.get('channel_id')) items = items.filter((h) => h.channel_id === query.get('channel_id'))
      const result = query.get('result')
      if (result && !['ok', 'failed'].includes(result)) throw invalid('result', 'ok or failed')
      if (result) items = items.filter((h) => h.result === result)
      if (query.get('alert_id')) items = items.filter((h) => (h.alert_ids || []).includes(query.get('alert_id')))
      const from = Date.parse(query.get('from') || '')
      const to = Date.parse(query.get('to') || '')
      if (Number.isFinite(from)) items = items.filter((h) => Date.parse(h.ts) >= from)
      if (Number.isFinite(to)) items = items.filter((h) => Date.parse(h.ts) <= to)
      const out = paginate(items, query)
      return { ...out, items: out.items.map(publicHistory) }
    },
  }
}
