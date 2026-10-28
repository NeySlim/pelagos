// SPDX-License-Identifier: Apache-2.0
// Encrypted archives of the mock (architecture section 23): destinations, age recipients (the
// cluster identity plus operator keys), archives per node, runs as jobs, inspect and restore plans.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

export const DESTINATION_TYPES = ['peer', 'mounted', 'sftp']
const DESTINATION_SECRETS = { peer: [], mounted: [], sftp: ['ssh_key'] }
const PARTS = [
  { id: 'bind.managed', engine: 'bind' },
  { id: 'bind.zones', engine: 'bind' },
  { id: 'kea4.config', engine: 'kea4' },
  { id: 'd2.config', engine: 'd2' },
  { id: 'pelagos.settings', engine: null },
]

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

const fakeRecipient = () => `age1${Array.from({ length: 58 }, () => 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[Math.floor(Math.random() * 32)]).join('')}`

export function archivesHandlers(state, { Problem, invalid, createPlan }) {
  const now = Date.now()
  state.archives ||= {
    destinations: [{ id: 'dst-peer', type: 'peer', name: 'Other nodes', enabled: true, params: {}, secrets: {}, keep: null }],
    recipients: [{ recipient: fakeRecipient(), label: 'cluster', kind: 'cluster', added_at: iso(now - 7 * 86400000), added_by: 'admin', downloaded_at: iso(now - 7 * 86400000) }],
    identity: { stored: true, downloaded_at: iso(now - 7 * 86400000) },
    list: state.nodes.map((node, i) => ({
      id: ulid(now - 3600000 - i), node_id: node.peer.id, created_at: iso(now - 3600000 - i * 900000), size: 1843200 + i * 1024,
      sha256: 'sha256:' + 'ab'.repeat(32), destinations: ['local', 'dst-peer'], complete: true,
      versions: { pelagos: '0.2.0', bind: '9.20.15', kea: '2.6.3' }, verified_at: iso(now - 3500000),
    })),
  }
  const a = state.archives
  const publicDestination = (d) => ({ ...d, secrets: Object.fromEntries((DESTINATION_SECRETS[d.type] || []).map((k) => [k, Boolean(d.secrets?.[k])])) })
  const destinationOf = (id) => {
    const d = a.destinations.find((x) => x.id === id)
    if (!d) throw new Problem(404, 'not_found', `destination ${id} not found`)
    return d
  }
  const archiveOf = (id) => {
    const found = a.list.find((x) => x.id === id)
    if (!found) throw new Problem(404, 'not_found', `archive ${id} not found`)
    return found
  }
  const check = (d) => {
    if (!DESTINATION_TYPES.includes(d.type)) throw invalid('type', `one of ${DESTINATION_TYPES.join(', ')}`)
    if (d.type === 'mounted' && !String(d.params?.path || '').startsWith('/')) throw invalid('params.path', 'an absolute path')
    if (d.type === 'sftp' && !d.params?.host_key_fingerprint) throw invalid('params.host_key_fingerprint', 'required')
  }
  const applySecrets = (d, secrets = {}) => {
    d.secrets ||= {}
    for (const [k, v] of Object.entries(secrets)) {
      if (!(DESTINATION_SECRETS[d.type] || []).includes(k)) throw invalid(`secrets.${k}`, 'unknown secret for this destination type')
      if (v === null) delete d.secrets[k]
      else d.secrets[k] = v
    }
  }
  const nodesState = () => state.nodes.map((node) => {
    const last = a.list.find((x) => x.node_id === node.peer.id)
    return { node_id: node.peer.id, last_success: last?.created_at || null, last_error: null, next_run: iso(Date.now() + 12 * 3600000), running: false, complete: last?.complete ?? null }
  })

  return {
    'GET /admin/archives': () => ({
      settings: { ...state.settings.archives },
      recipients: a.recipients,
      identity: a.identity,
      destinations: a.destinations.map(publicDestination),
      nodes: nodesState(),
    }),
    'POST /admin/archives/destinations': ({ body, user, res }) => {
      const d = { id: ulid(), type: body.type, name: body.name || body.type, enabled: body.enabled ?? true, params: body.params || {}, secrets: {}, keep: body.keep || null }
      check(d)
      applySecrets(d, body.secrets)
      a.destinations.push(d)
      auditEntry(state, user, { action: 'admin.archive.add', target: `archive-destination:${d.id}` })
      res.statusCode = 201
      return publicDestination(d)
    },
    'POST /admin/archives/destinations/test': ({ body }) => {
      if (body.destination_id) destinationOf(body.destination_id)
      else check(body)
      return { ok: true, node_id: state.selfId }
    },
    'PUT /admin/archives/destinations/{id}': ({ params, body, user }) => {
      const d = destinationOf(params.id)
      const next = { ...d }
      for (const k of ['name', 'enabled', 'params', 'keep']) if (k in body) next[k] = body[k]
      check(next)
      applySecrets(next, body.secrets)
      Object.assign(d, next)
      auditEntry(state, user, { action: 'admin.archive.replace', target: `archive-destination:${d.id}` })
      return publicDestination(d)
    },
    'DELETE /admin/archives/destinations/{id}': ({ params, user }) => {
      destinationOf(params.id)
      a.destinations = a.destinations.filter((d) => d.id !== params.id)
      auditEntry(state, user, { action: 'admin.archive.delete', target: `archive-destination:${params.id}` })
      return null
    },
    'POST /admin/archives/run': ({ body, user, res }) => {
      const ids = body.node_ids || state.nodes.map((node) => node.peer.id)
      const t = Date.now()
      for (const id of ids) {
        a.list.unshift({ id: ulid(t), node_id: id, created_at: iso(t), size: 1843200, sha256: 'sha256:' + 'cd'.repeat(32), destinations: ['local', ...a.destinations.filter((d) => d.enabled).map((d) => d.id)], complete: true, versions: { pelagos: '0.2.0', bind: '9.20.15', kea: '2.6.3' }, verified_at: iso(t) })
      }
      const steps = ids.map((id) => ({ name: `archive:${id}`, state: 'done', output: 'ok', started_at: iso(t), finished_at: iso(t) }))
      const job = { id: ulid(t), plan_id: null, state: 'done', progress: 100, steps, created_at: iso(t), finished_at: iso(t), error: null }
      state.jobs.set(job.id, job)
      auditEntry(state, user, { action: 'archive.create', target: 'archives', request: { node_ids: ids } })
      res.statusCode = 202
      return job
    },
    'GET /admin/archives/list': ({ query }) => {
      let items = a.list
      if (query.get('node_id')) items = items.filter((x) => x.node_id === query.get('node_id'))
      if (query.get('destination_id')) items = items.filter((x) => x.destinations.includes(query.get('destination_id')))
      return paginate(items, query)
    },
    'POST /admin/archives/upload': ({ user, res }) => {
      const t = Date.now()
      const entry = { id: ulid(t), node_id: state.selfId, created_at: iso(t), size: 1024, sha256: 'sha256:' + 'ef'.repeat(32), destinations: ['local'], complete: true, versions: { pelagos: '0.2.0' }, verified_at: null }
      a.list.unshift(entry)
      auditEntry(state, user, { action: 'admin.archive.op', target: `archive:${entry.id}`, request: { op: 'upload' } })
      res.statusCode = 201
      return entry
    },
    'POST /admin/archives/identity': ({ body, user }) => {
      const op = body.op
      if (op === 'generate' || op === 'rotate') {
        const recipient = fakeRecipient()
        a.recipients = [{ recipient, label: 'cluster', kind: 'cluster', added_at: iso(Date.now()), added_by: user.username, downloaded_at: iso(Date.now()) }, ...a.recipients.filter((r) => r.kind !== 'cluster')]
        a.identity = { stored: true, downloaded_at: iso(Date.now()) }
        auditEntry(state, user, { action: 'admin.archive.op', target: 'archive:identity', request: { op } })
        return { recipients: a.recipients, identity: `AGE-SECRET-KEY-1MOCK${'Q'.repeat(54)}` }
      }
      if (op === 'add_recipient') {
        if (!/^age1[0-9a-z]{58}$/.test(body.recipient || '')) throw invalid('recipient', 'an age X25519 recipient (age1...)')
        if (a.recipients.some((r) => r.recipient === body.recipient)) throw new Problem(409, 'conflict', 'recipient already listed')
        a.recipients.push({ recipient: body.recipient, label: body.label || '', kind: 'operator', added_at: iso(Date.now()), added_by: user.username })
      } else if (op === 'remove_recipient') {
        const r = a.recipients.find((x) => x.recipient === body.recipient)
        if (!r) throw new Problem(404, 'not_found', 'recipient not listed')
        if (r.kind === 'cluster') throw new Problem(409, 'conflict', 'the cluster recipient is replaced by rotate')
        a.recipients = a.recipients.filter((x) => x !== r)
      } else {
        throw invalid('op', 'one of generate, rotate, add_recipient, remove_recipient')
      }
      auditEntry(state, user, { action: 'admin.archive.op', target: 'archive:recipients', request: { op, recipient: body.recipient } })
      return { recipients: a.recipients }
    },
    'GET /admin/archives/{id}/download': ({ params, user }) => {
      const found = archiveOf(params.id)
      auditEntry(state, user, { action: 'admin.archive.op', target: `archive:${found.id}`, request: { op: 'download' } })
      return { id: found.id, note: 'the real endpoint streams application/octet-stream' }
    },
    'POST /admin/archives/{id}/inspect': ({ params }) => {
      const found = archiveOf(params.id)
      return {
        manifest: { node_id: found.node_id, created_at: found.created_at, versions: found.versions, files: 42, unreadable: [] },
        parts: PARTS.map((p) => ({ ...p, node_id: found.node_id, files: 3, diff_summary: { added: 0, removed: 0, changed: p.id === 'bind.zones' ? 2 : 0 } })),
      }
    },
    'POST /admin/archives/{id}/restore/plan': ({ params, body, user }) => {
      const found = archiveOf(params.id)
      const parts = body.parts?.length ? body.parts : ['pelagos.settings']
      return createPlan(state, user, {
        scope: 'restore',
        summary: `restore ${parts.join(', ')} from the archive of ${found.created_at}`,
        changes: parts.map((p) => ({ op: 'replace', target: `restore/${p}`, before: null, after: { archive_id: found.id } })),
        targets: [body.target_node_id || state.selfId],
        requires_confirmation: true,
        job: parts.map((p) => `restore:${p}`),
      })
    },
  }
}
