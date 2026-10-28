// SPDX-License-Identifier: Apache-2.0
// Encrypted archives of the mock (architecture section 23), shaped like services/archive_service.py:
// settings, age recipients (the cluster identity once, operator keys), destinations with a
// write-only SSH key and a test, runs as jobs, the merged list of every node, download, upload,
// inspect and restore plans (services/archive_restore.py).
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

export const DESTINATION_TYPES = ['peer', 'mounted', 'sftp']
const MANAGED = ['destinations', 'recipients']
const SFTP_TARGET = ['host', 'port', 'username']
const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}=?$/
const KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/
const RECIPIENT_RE = /^age1[0-9a-z]{58}$/
const VERSIONS = { pelagos: '0.2.2', bind: '9.20.15', kea: '2.6.3' }

function paginate(items, query) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  return { items: items.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: items.length }
}

const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
const randomRecipient = () => `age1${Array.from({ length: 58 }, () => BECH32[Math.floor(Math.random() * 32)]).join('')}`
const randomIdentity = () => `AGE-SECRET-KEY-1${Array.from({ length: 58 }, () => BECH32[Math.floor(Math.random() * 32)].toUpperCase()).join('')}`

export function hasRecipient(state) {
  return (state.archives?.recipients || []).some((r) => RECIPIENT_RE.test(r.recipient))
}

export function archivesHandlers(state, { Problem, invalid, createPlan }) {
  const now = Date.now()
  const nodeIds = state.nodes.map((n) => n.peer.id)
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const archive = (nodeId, t, extra = {}) => ({
    id: ulid(t), node_id: nodeId, node_name: nameOf(nodeId), created_at: iso(t), size: 1843200 + (t % 4096),
    sha256: 'ab'.repeat(32), destinations: ['local', 'dst-peer'], complete: true, versions: VERSIONS,
    verified_at: iso(t + 60000), filename: `${nameOf(nodeId)}-${new Date(t).toISOString().replace(/[-:]/g, '').slice(0, 15)}Z.tar.gz.age`,
    recipients: null, held_by: [nodeId, ...nodeIds.filter((x) => x !== nodeId).slice(0, 1)], ...extra,
  })
  state.archives ||= {
    destinations: [{ id: 'dst-peer', type: 'peer', name: 'Other nodes', enabled: true, params: { node_ids: [] }, keep: null, ssh_key: null }],
    recipients: [{ recipient: randomRecipient(), label: 'cluster', kind: 'cluster', added_at: iso(now - 7 * 86400000), added_by: 'admin', downloaded_at: iso(now - 7 * 86400000) }],
    retired: [],
    list: nodeIds.flatMap((id, i) => [archive(id, now - 3600000 - i * 900000), archive(id, now - 90000000 - i * 900000)]),
    runs: Object.fromEntries(nodeIds.map((id) => [id, { failures: {}, errors: {}, last_error: null }])),
  }
  const a = state.archives
  const settings = () => Object.fromEntries(Object.entries(state.settings.archives || {}).filter(([k]) => !MANAGED.includes(k)))
  const identityState = () => {
    const cluster = a.recipients.find((r) => r.kind === 'cluster')
    return { stored: Boolean(cluster), recipient: cluster?.recipient || null, downloaded_at: cluster?.downloaded_at || null, retired: [...a.retired] }
  }
  const nodes = () => nodeIds.map((id) => {
    const own = a.list.filter((x) => x.node_id === id && x.destinations.includes('local'))
    const last = own[0] || null
    const run = a.runs[id] || { failures: {}, errors: {} }
    return {
      node_id: id, name: nameOf(id), reachable: true, error: null,
      last_attempt: last?.created_at || null, last_success: last?.created_at || null, last_error: run.last_error,
      last_archive: last, count: own.length,
      next_run: settings().schedule_enabled ? iso(Date.now() + 12 * 3600000) : null, running: false,
      complete: last?.complete ?? null, unreadable: [], failures: run.failures, errors: run.errors,
      last_test_restore: last?.created_at || null,
      test_restore: last ? { ok: true, at: last.created_at, archive_id: last.id, checks: [{ what: 'named-checkconf', ok: true, output: '' }] } : null,
    }
  })
  const destinationError = (d) => {
    if (d.type === 'mounted' && !String(d.params?.path || '').startsWith('/')) return 'params.path must be an absolute path'
    if (d.type === 'sftp') {
      if (!d.params?.host) return 'params.host must be a host name or an address'
      if (!d.params?.username) return 'params.username is required'
      if (!FP_RE.test(d.params?.host_key_fingerprint || '')) return 'params.host_key_fingerprint must be SHA256:... (ssh-keygen -lf)'
    }
    return null
  }
  const publicDestination = (d) => ({
    id: d.id, type: d.type, name: d.name, enabled: d.enabled, params: d.params, keep: d.keep ?? null,
    secrets: d.type === 'sftp' ? { ssh_key: Boolean(d.ssh_key) } : {},
    error: destinationError(d),
    status: nodeIds.filter((id) => a.runs[id]?.failures?.[d.id]).map((id) => ({ node_id: id, failures: a.runs[id].failures[d.id], error: a.runs[id].errors[d.id] || null })),
  })
  const destinationOf = (id) => {
    const d = a.destinations.find((x) => x.id === id)
    if (!d) throw new Problem(404, 'not_found', `destination ${id} not found`)
    return d
  }
  const archiveOf = (id) => {
    const found = a.list.find((x) => x.id === id)
    if (!found) throw new Problem(404, 'not_found', `archive ${id}: held by no reachable node`)
    return found
  }
  const many = (errors) => new Problem(400, 'validation_error', `invalid destination: ${errors.map((e) => e.field).join(', ')}`, errors)
  // { given, value } of secrets.ssh_key: a string sets it, null clears it, absent keeps it.
  const keyIn = (body, type, errors) => {
    const raw = body.secrets
    if (!raw || !('ssh_key' in raw)) return { given: false, value: null }
    if (type !== 'sftp') {
      errors.push({ field: 'secrets.ssh_key', message: 'only an sftp destination has a key' })
      return { given: false, value: null }
    }
    const v = raw.ssh_key
    if (v === null || v === '') return { given: true, value: null }
    if (typeof v !== 'string' || !KEY_RE.test(v)) {
      errors.push({ field: 'secrets.ssh_key', message: 'an unencrypted private key (BEGIN ... PRIVATE KEY)' })
      return { given: false, value: null }
    }
    return { given: true, value: v }
  }
  const check = (d, errors) => {
    if (!DESTINATION_TYPES.includes(d.type)) errors.push({ field: 'type', message: `type must be one of ${DESTINATION_TYPES.join(', ')}` })
    if (!String(d.name || '').trim()) errors.push({ field: 'name', message: 'required' })
    const problem = DESTINATION_TYPES.includes(d.type) && destinationError(d)
    if (problem) errors.push({ field: problem.split(' ')[0], message: problem })
    for (const id of d.type === 'peer' ? d.params?.node_ids || [] : []) {
      if (!nodeIds.includes(id)) errors.push({ field: 'params.node_ids', message: `unknown node ${id}` })
    }
  }
  const requirePassword = (user, password) => {
    const record = state.users.find((u) => u.id === user.id)
    if (!record || record.password !== password) throw new Problem(401, 'invalid_credentials', 'password is wrong')
  }

  return {
    'GET /admin/archives': () => ({
      settings: settings(),
      recipients: a.recipients,
      identity: identityState(),
      destinations: a.destinations.map(publicDestination),
      nodes: nodes(),
    }),
    'PUT /admin/archives/settings': ({ body, user }) => {
      const errors = []
      for (const k of Object.keys(body)) {
        if (MANAGED.includes(k) || !(k in (state.settings.archives || {}))) errors.push({ field: k, message: MANAGED.includes(k) ? 'set through its own screen' : 'unknown setting' })
      }
      if (body.start_time !== undefined && !/^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(body.start_time)) errors.push({ field: 'start_time', message: 'HH:MM expected' })
      if (body.schedule_enabled === true && !hasRecipient(state)) errors.push({ field: 'schedule_enabled', message: 'no archive recipient' })
      if (errors.length) throw new Problem(400, 'validation_error', 'invalid archive settings', errors)
      state.settings.archives = { ...state.settings.archives, ...body }
      auditEntry(state, user, { action: 'admin.settings.replace', target: 'settings', request: { archives: body } })
      return { settings: settings() }
    },
    'POST /admin/archives/destinations': ({ body, user, res }) => {
      const errors = []
      const d = { id: ulid().toLowerCase(), type: body.type, name: String(body.name || '').trim(), enabled: body.enabled ?? true, params: body.params || {}, keep: body.keep ?? null, ssh_key: null }
      const key = keyIn(body, d.type, errors)
      check(d, errors)
      if (d.type === 'sftp' && !key.value) errors.push({ field: 'secrets.ssh_key', message: 'required' })
      if (errors.length) throw many(errors)
      d.ssh_key = key.value
      a.destinations.push(d)
      auditEntry(state, user, { action: 'admin.archive.add', target: `archive-destination:${d.id}` })
      res.statusCode = 201
      return publicDestination(d)
    },
    'POST /admin/archives/destinations/test': ({ body }) => {
      let d
      if (body.destination_id) d = destinationOf(body.destination_id)
      else {
        const errors = []
        d = { id: body.scope || 'test', type: body.type, name: body.name || 'test', enabled: true, params: body.params || {}, keep: null }
        const key = keyIn(body, d.type, errors)
        check(d, errors)
        if (errors.length) throw many(errors)
        const saved = body.scope && a.destinations.find((x) => x.id === body.scope)
        const same = saved && SFTP_TARGET.every((k) => saved.params?.[k] === d.params?.[k])
        d.ssh_key = key.given ? key.value : same ? saved.ssh_key : null
      }
      const host = String(d.params?.host || '')
      const targets = d.type === 'peer'
        ? nodeIds.filter((id) => id !== state.selfId && (!d.params?.node_ids?.length || d.params.node_ids.includes(id))).map((id) => ({ label: nameOf(id), node_id: id, ok: true, free_bytes: 40e9 }))
        : d.type === 'sftp' && !d.ssh_key ? [{ label: d.name, ok: false, error: `no SSH key stored for ${d.name}` }]
          : host.includes('unreachable') || String(d.params?.path || '').includes('unmounted')
            ? [{ label: d.name, ok: false, error: d.type === 'mounted' ? `${d.params.path} is not a mount point` : `connection to ${host} refused` }]
            : [{ label: d.name, ok: true }]
      const ok = targets.length > 0 && targets.every((t) => t.ok)
      return { ok, node_id: state.selfId, targets, ...(ok ? {} : { error: targets.map((t) => t.error).filter(Boolean).join('; ') }) }
    },
    'PUT /admin/archives/destinations/{id}': ({ params, body, user }) => {
      const d = destinationOf(params.id)
      const errors = []
      if ('type' in body && body.type !== d.type) errors.push({ field: 'type', message: 'a destination keeps its type: create a new one' })
      const next = { ...d }
      for (const k of ['name', 'enabled', 'params', 'keep']) if (k in body) next[k] = body[k]
      const key = keyIn(body, d.type, errors)
      check(next, errors)
      if (d.type === 'sftp' && d.ssh_key && !key.given && SFTP_TARGET.some((k) => d.params?.[k] !== next.params?.[k])) {
        errors.push({ field: 'secrets.ssh_key', message: 'enter it again or clear it: the server changed' })
      }
      if (errors.length) throw many(errors)
      if (key.given) next.ssh_key = key.value
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
      const ids = body.node_ids || nodeIds
      const unknown = ids.filter((id) => !nodeIds.includes(id))
      if (unknown.length) throw invalid('node_ids', `unknown: ${unknown.join(', ')}`)
      if (!hasRecipient(state)) throw new Problem(409, 'conflict', 'no archive recipient: generate the cluster archive key first')
      const t = Date.now()
      const steps = ids.map((id, i) => {
        const made = archive(id, t + i, { destinations: ['local', ...a.destinations.filter((d) => d.enabled).map((d) => d.id)], recipients: a.recipients.map((r) => r.recipient) })
        a.list.unshift(made)
        return { name: `archive:${nameOf(id)}`, label: `archive:${nameOf(id)}`, node_id: id, state: 'done', output: { archive_id: made.id, size: made.size, complete: true, errors: {} }, started_at: iso(t), finished_at: iso(t) }
      })
      const job = { id: ulid(t), plan_id: null, state: 'done', progress: 100, steps, created_at: iso(t), finished_at: iso(t), error: null }
      state.jobs.set(job.id, job)
      auditEntry(state, user, { action: 'admin.archive.op', target: 'archives:run', request: { op: 'run', node_ids: ids } })
      res.statusCode = 202
      return job
    },
    'GET /admin/archives/list': ({ query }) => {
      let items = a.list
      if (query.get('node_id')) items = items.filter((x) => x.node_id === query.get('node_id'))
      if (query.get('destination_id')) items = items.filter((x) => x.destinations.includes(query.get('destination_id')))
      return { ...paginate(items, query), meta: { unreachable: [] } }
    },
    'POST /admin/archives/upload': ({ req, user, res }) => {
      if (!String(req.headers['content-type'] || '').startsWith('multipart/form-data')) {
        throw invalid('file', 'a multipart field file is required')
      }
      const t = Date.now() - 30 * 86400000
      const entry = archive('n-lost', t, { node_name: 'old-ns', destinations: ['upload'], held_by: [state.selfId] })
      if (a.list.some((x) => x.filename === entry.filename)) throw new Problem(409, 'conflict', 'already held by this node')
      a.list.push(entry)
      a.list.sort((x, y) => (x.created_at < y.created_at ? 1 : -1))
      auditEntry(state, user, { action: 'admin.archive.op', target: `archive:${entry.id}`, request: { op: 'upload' } })
      res.statusCode = 201
      return entry
    },
    'POST /admin/archives/identity': ({ body, user }) => {
      const op = body.op
      const out = {}
      const cluster = a.recipients.find((r) => r.kind === 'cluster')
      if (op === 'generate' || op === 'rotate') {
        if (op === 'generate' && cluster) throw new Problem(409, 'conflict', 'the cluster already has an archive key: rotate it instead')
        if (op === 'rotate' && !cluster) throw new Problem(409, 'conflict', 'no cluster archive key to rotate: generate one')
        requirePassword(user, body.password)
        if (cluster) a.retired.push(cluster.recipient)
        const stamp = iso(Date.now())
        a.recipients = [{ recipient: randomRecipient(), label: body.label || 'cluster', kind: 'cluster', added_at: stamp, added_by: user.username, downloaded_at: stamp }, ...a.recipients.filter((r) => r.kind !== 'cluster')]
        out.identity = randomIdentity()
      } else if (op === 'add_recipient') {
        const recipient = String(body.recipient || '').trim()
        if (!RECIPIENT_RE.test(recipient)) throw invalid('recipient', 'not an age X25519 recipient (age1...)')
        if (a.recipients.some((r) => r.recipient === recipient)) throw invalid('recipient', 'recipient already present')
        a.recipients.push({ recipient, label: body.label || '', kind: 'operator', added_at: iso(Date.now()), added_by: user.username })
      } else if (op === 'remove_recipient') {
        const r = a.recipients.find((x) => x.recipient === body.recipient)
        if (!r) throw new Problem(404, 'not_found', 'unknown recipient')
        if (state.settings.archives?.schedule_enabled && a.recipients.length === 1) {
          throw new Problem(409, 'conflict', 'scheduled archives need a recipient: disable the schedule first')
        }
        if (r.kind === 'cluster') a.retired.push(r.recipient)
        a.recipients = a.recipients.filter((x) => x !== r)
      } else if (op === 'prune_retired') {
        const used = new Set(a.list.flatMap((x) => x.recipients || []))
        out.dropped = a.retired.filter((r) => !used.has(r))
        out.kept_because = a.list.some((x) => x.recipients === null) && a.retired.length ? 'an archive without recorded recipients is still kept' : null
        if (out.kept_because) out.dropped = []
        a.retired = a.retired.filter((r) => !out.dropped.includes(r))
      } else {
        throw invalid('op', 'op must be one of generate, rotate, add_recipient, remove_recipient, prune_retired')
      }
      auditEntry(state, user, { action: 'admin.archive.op', target: 'archives:identity', request: { op, recipient: body.recipient } })
      return { recipients: a.recipients, identity_state: identityState(), ...out }
    },
    'GET /admin/archives/{id}/download': ({ params, user, res }) => {
      const found = archiveOf(params.id)
      auditEntry(state, user, { action: 'admin.archive.op', target: `archive:${found.id}`, request: { op: 'download' } })
      res.setHeader('content-type', 'application/octet-stream')
      res.setHeader('content-disposition', `attachment; filename="${found.filename}"`)
      return { raw: 'age-encryption.org/v1\n' }
    },
    'POST /admin/archives/{id}/inspect': ({ params, body }) => {
      const found = archiveOf(params.id)
      if (body.identity && !/^AGE-SECRET-KEY-1[0-9A-Z]{58}$/.test(body.identity)) throw invalid('identity', 'invalid')
      const target = body.target_node_id || (nodeIds.includes(found.node_id) ? found.node_id : state.selfId)
      const moved = target !== found.node_id
      const subs = body.substitute || {}
      const part = (id, engine, permission, summary, extra = {}) => ({ id, engine, node_id: engine === 'pelagos' ? state.selfId : target, files: [], permission, diff_summary: summary, ...extra })
      return {
        manifest: {
          format: 1, archive_id: found.id, node_id: found.node_id, node_name: found.node_name, created_at: found.created_at, versions: found.versions,
          engines: ['bind', 'kea4', 'd2'], hashes: {}, files: [], zones: [{ view: '_default', zone: 'example.lan', serial: 2026102801, source: 'axfr', sha256: '' }],
          unreadable: [], complete: found.complete,
        },
        archive: found,
        target_node_id: target,
        parts: [
          part('bind.managed', 'bind', 'write:dns.config', { changed: ['pelagos/zones.conf'], unchanged: 3, plans: 1, valid: true }, { files: ['/etc/bind/pelagos/zones.conf'] }),
          part('bind.user_files', 'bind', 'write:dns.config', { changed: false, unchanged: 2 }, { requires: 'include_user_files' }),
          part('bind.zone:_default/example.lan', 'bind', 'write:dns.records', { add: 2, replace: 1, delete: 0, skipped: { RRSIG: 4 }, refused: [], plans: 1, valid: true }, { mode: 'diff', modes: ['diff', 'replace'] }),
          part('kea4.config', 'kea4', 'write:dhcp.config', { changed: true, lines: 6, plans: 1, valid: true }),
          part('d2.config', 'd2', 'write:dhcp.config', { changed: false }),
          part('pelagos.settings:settings', 'pelagos', 'admin:settings', { changed: true }),
          part('pelagos.settings:users', 'pelagos', 'admin:users', { changed: false }),
          part('pelagos.audit', 'pelagos', 'admin:archives', { entries: 12 }),
        ],
        warnings: moved && !subs['192.0.2.12'] ? [{ part: 'kea4.config', old_node: found.node_id, found: ['192.0.2.12', found.node_name] }] : [],
      }
    },
    'POST /admin/archives/{id}/restore/plan': ({ params, body, user }) => {
      const found = archiveOf(params.id)
      const parts = (body.parts || []).map((p) => (typeof p === 'string' ? p : p.id))
      if (!parts.length) throw invalid('parts', 'choose at least one part')
      if (parts.includes('bind.user_files') && !body.include_user_files) throw invalid('parts', 'bind.user_files needs include_user_files')
      const target = body.target_node_id || state.selfId
      return createPlan(state, user, {
        scope: 'restore',
        summary: `restore from the archive of ${found.created_at} on ${nameOf(target)}`,
        summary_message: { key: 'plan.restore', params: { archive: found.created_at, node: nameOf(target) } },
        changes: parts.map((p) => ({ op: 'replace', target: p.startsWith('pelagos.') ? `cluster:${p.split(':')[1] || 'audit'}` : `restore/${p}`, before: null, after: { archive_id: found.id } })),
        diff: parts.includes('kea4.config') ? '--- kea-dhcp4.conf\n+++ kea-dhcp4.conf (archive)\n-  "valid-lifetime": 3600,\n+  "valid-lifetime": 7200,\n' : '',
        targets: [target],
        requires_confirmation: true,
        job: parts.map((p) => `restore:${p}`),
      })
    },
  }
}
