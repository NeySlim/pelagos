// SPDX-License-Identifier: Apache-2.0
// Updates from the UI of the mock (architecture section 29): nodes and versions, available releases
// (signed, unsigned or signed by an unknown key), upload, plans of scope update, a rollout that
// advances with time (updateStepMs, 0: at once), resume, cancel, rollback, history, engine packages.
// A release whose package name contains "broken" fails on the second node at the health step.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

const msg = (key, params = {}) => ({ key, params })
const KEY_ID = 'a1b2c3d4e5f60718'
const NOTES = '# Pelagos 0.3.0\n\n- Kea 3.x migration assistant\n- Updates from the UI\n\n    sha256  pelagos_0.3.0-1_amd64.deb\n'
const PELAGOS_STEPS = ['wait', 'fetch', 'verify', 'precheck', 'backup', 'install', 'version', 'restart', 'settle', 'health', 'convergence', 'audit', 'journal', 'ha']
const ENGINE_STEPS = ['wait', 'precheck', 'ha_maintenance', 'install', 'version', 'restart', 'engine_checks', 'ha']
const ROLLOUT_STATES_ACTIVE = new Set(['running', 'failed'])
const REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/
const VERSION_RE = /^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}([~+.-][A-Za-z0-9.~+-]{1,40})?$/

// Dotted numeric compare of the upstream part (enough for the mock's versions).
export function compareVersions(a, b) {
  const parts = (v) => String(v).split(/[~+-]/)[0].split('.').map(Number)
  const [x, y] = [parts(a), parts(b)]
  for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0)
  return 0
}

function release(version, extra = {}) {
  return {
    version, source: 'github', published_at: iso(Date.now() - 2 * 86400000), notes: NOTES.replaceAll('0.3.0', version),
    signature: 'valid', signed: true, key_id: KEY_ID, state_schema: 1, min_upgrade_from: '0.2.4',
    files: ['NOTES.md', 'SHA256SUMS', 'SHA256SUMS.sig', 'release.json', `pelagos_${version}-1_amd64.deb`, `pelagos_${version}-1_arm64.deb`],
    broken: false, ...extra,
  }
}

// The available entry of a release: without the mock's own fields.
const publicRelease = (r) => Object.fromEntries(Object.entries(r).filter(([k]) => k !== 'broken' && k !== 'files'))

// Filenames and the SHA256SUMS.sig part of a multipart body (the mock does not parse the rest).
function multipartFiles(raw) {
  const files = {}
  const text = String(raw || '')
  const re = /filename="([^"]+)"\r?\n(?:[^\r\n]+\r?\n)*\r?\n([\s\S]*?)\r?\n--/g
  let m
  while ((m = re.exec(text))) files[m[1].split('/').pop()] = m[2]
  return files
}

export function updatesHandlers(state, { Problem, invalid, createPlan }) {
  state.updates ||= {
    releases: [release('0.3.1')],
    rollout: null,
    history: [],
    github_repository: 'example/pelagos',
    github_token_stored: false,
    previous: {},
    checked_at: iso(Date.now() - 3600000),
  }
  const u = state.updates
  const settings = () => state.settings.updates || {}
  const nameOf = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
  const stepMs = () => state.updateStepMs || 0
  const nodes = () => state.nodes.map((n, i) => ({
    node_id: n.peer.id, name: n.peer.name, version: n.version, arch: i % 2 ? 'arm64' : 'amd64', package_format: 'deb',
    previous_kept: u.previous[n.peer.id] || null, state_schema: 1, reachable: n.status === 'online',
  }))
  const engines = () => state.nodes.flatMap((n) => [
    { node_id: n.peer.id, engine: 'bind', package: 'bind9', installed: '1:9.20.11-4', candidate: '1:9.20.15-1~deb13u1', cves: ['CVE-2025-40778', 'CVE-2025-40780'] },
    { node_id: n.peer.id, engine: 'kea4', package: 'kea-dhcp4-server', installed: '2.6.3-1', candidate: null, cves: [] },
  ])
  // Default order (section 29): every node but the active DNS primary, the primary (this node) last.
  const defaultOrder = (ids) => [...ids.filter((id) => id !== state.selfId), ...ids.filter((id) => id === state.selfId)]
  const raise = (kind, severity, subject, title, title_message, details) => {
    const now = iso(Date.now())
    const alert = { id: ulid(), kind, severity, state: 'open', node_id: null, engine: null, subject, title, title_message, details, first_seen: now, last_seen: now, acked_by: null, acked_at: null, resolved_at: null, reported_by: [state.selfId] }
    state.alerts.unshift(alert)
    state.emit?.('alerts', 'opened', alert)
  }
  const finish = (r, rolloutState) => {
    r.state = rolloutState
    r.finished_at = iso(Date.now())
    u.history.unshift({ id: r.id, kind: r.kind, version: r.version, state: r.state, created_by: r.created_by, created_at: r.created_at, finished_at: r.finished_at, nodes: r.nodes.map((n) => ({ node_id: n.node_id, state: n.state, from_version: n.from_version, to_version: n.to_version, error: n.error })) })
  }

  // Moves the rollout forward from the time elapsed since each node started.
  const advance = () => {
    const r = u.rollout
    if (!r || r.state !== 'running') return
    const steps = r.kind === 'engine_packages' ? ENGINE_STEPS : PELAGOS_STEPS
    const rel = u.releases.find((x) => x.version === r.version)
    for (const [i, n] of r.nodes.entries()) {
      if (['done', 'rolled_back', 'skipped'].includes(n.state)) continue
      if (n.state === 'failed') return
      const now = Date.now()
      if (n.state === 'pending') {
        n.state = 'running'
        n.started_at = iso(now)
        n.step = steps[0]
        auditEntry(state, null, { action: 'update.node.start', target: `update:${r.id}`, request: { node_id: n.node_id, version: r.version } })
      }
      const done = stepMs() ? Math.floor((now - Date.parse(n.started_at)) / stepMs()) : steps.length
      const failAt = rel?.broken && i === 1 ? steps.indexOf('health') : -1
      if (failAt >= 0 && done >= failAt) {
        n.step = 'health'
        n.error = 'health: /api/v1/health did not answer within 300 s'
        n.error_message = msg('alert.update_failed', { version: r.version, node: nameOf(n.node_id), step: 'health', error: 'no health answer' })
        n.finished_at = iso(now)
        const back = r.auto_rollback && !r.state_schema_changed
        n.state = back ? 'rolled_back' : 'failed'
        if (back) n.to_version = n.from_version
        auditEntry(state, null, { action: back ? 'update.node.rolled_back' : 'update.node.failed', target: `update:${r.id}`, result: 'error', request: { node_id: n.node_id, step: 'health' }, message: n.error })
        raise('update_failed', 'critical', `update:${r.id}`, `update to ${r.version} failed on ${nameOf(n.node_id)} at step health: ${n.error}`, n.error_message, { rollout_id: r.id, node_id: n.node_id, step: 'health', version: r.version, rolled_back: back })
        r.state = 'failed'
        return
      }
      if (done < steps.length) {
        n.step = steps[done]
        return
      }
      n.state = 'done'
      n.step = null
      n.finished_at = iso(now)
      const node = state.nodes.find((x) => x.peer.id === n.node_id)
      if (node && r.kind !== 'engine_packages') {
        if (r.kind === 'pelagos') u.previous[n.node_id] = node.version
        node.version = n.to_version
      }
      auditEntry(state, null, { action: 'update.node.done', target: `update:${r.id}`, request: { node_id: n.node_id, version: n.to_version } })
    }
    finish(r, 'done')
  }

  const rolloutOf = (kind, version, order, extra = {}) => ({
    id: ulid(), kind, version, state: 'running', order,
    nodes: order.map((id) => ({ node_id: id, state: 'pending', step: null, started_at: null, finished_at: null, error: null, error_message: null, from_version: state.nodes.find((n) => n.peer.id === id)?.version || null, to_version: version })),
    created_at: iso(Date.now()), finished_at: null, plan_id: null, source: null, artifacts: {}, packages: {}, auto_rollback: settings().auto_rollback_enabled ?? true,
    state_schema_changed: false, signature: 'valid', key_id: null, unsigned_accepted_by: null, unsigned_accepted_at: null, ...extra,
  })

  const requirePassword = (user, password) => {
    if (!password) throw invalid('password', 'the password of the user is required')
    const record = state.users.find((x) => x.id === user.id)
    if (!record || record.password !== password) throw new Problem(401, 'invalid_credentials', 'password is wrong')
  }

  return {
    'GET /admin/updates': () => {
      advance()
      return {
        nodes: nodes(), available: u.releases.map(publicRelease), rollout: u.rollout,
        settings: { ...settings(), github_repository: u.github_repository, github_token_stored: u.github_token_stored },
        engines: engines(), checked_at: u.checked_at, docker: null,
      }
    },
    'POST /admin/updates/check': ({ user }) => {
      if (settings().source === 'github' && !u.github_repository) throw new Problem(409, 'conflict', 'no GitHub repository is set')
      u.checked_at = iso(Date.now())
      auditEntry(state, user, { action: 'admin.update.check', target: 'updates', request: { source: settings().source || 'upload' } })
      return { available: u.releases.map(publicRelease), checked_at: u.checked_at, error: null }
    },
    'POST /admin/updates/upload': ({ req, raw, user, res }) => {
      if (!String(req.headers['content-type'] || '').startsWith('multipart/form-data')) throw invalid('files', 'the files of a release directory, as multipart fields files')
      const files = multipartFiles(raw)
      const names = Object.keys(files)
      const refuse = (reason, params) => {
        const p = new Problem(422, 'release_invalid', `release refused: ${reason}`)
        p.extra = { reason, detail_message: msg(`update.refused.${reason}`, params) }
        throw p
      }
      if (!names.includes('SHA256SUMS')) refuse('missing', { file: 'SHA256SUMS' })
      const pkg = names.find((f) => f.endsWith('.deb') || f.endsWith('.rpm'))
      if (!pkg) refuse('arch', { format: 'deb', arch: 'amd64' })
      const m = /^pelagos_([^_]+?)(-\d+)?_[a-z0-9]+\.(deb|rpm)$/.exec(pkg)
      if (!m || !VERSION_RE.test(m[1])) refuse('name', { file: pkg, package: 'pelagos' })
      const sig = files['SHA256SUMS.sig']
      if (sig !== undefined && /tampered|invalid/.test(sig)) refuse('signature_invalid', {})
      const signature = sig === undefined ? 'unsigned' : /0000000000000000/.test(sig) ? 'unknown_key' : 'valid'
      const entry = release(m[1], { source: 'upload', published_at: iso(Date.now()), signature, signed: signature === 'valid', key_id: signature === 'unsigned' ? null : signature === 'valid' ? KEY_ID : '0000000000000000', files: names, broken: pkg.includes('broken') })
      u.releases = [...u.releases.filter((r) => r.version !== entry.version), entry].sort((a, b) => compareVersions(b.version, a.version))
      auditEntry(state, user, { action: 'admin.update.upload', target: `release:${entry.version}`, request: { files: names }, response: { signature } })
      res.statusCode = 201
      return { version: entry.version, files: names, signature, signed: entry.signed, key_id: entry.key_id, state_schema: entry.state_schema }
    },
    'PUT /admin/updates/settings': ({ body, user }) => {
      const { github_repository: repo, github_token: token, ...rest } = body
      const errors = []
      if (repo !== undefined && repo !== '' && !REPO_RE.test(repo)) errors.push({ field: 'github_repository', message: 'owner/name expected' })
      const source = rest.source ?? settings().source
      if (source === 'github' && !(repo ?? u.github_repository)) errors.push({ field: 'github_repository', message: 'required with the github source' })
      if (errors.length) throw new Problem(400, 'validation_error', 'invalid update settings', errors)
      state.settings.updates = { ...settings(), ...rest }
      if (repo !== undefined) u.github_repository = repo
      if (token !== undefined) u.github_token_stored = Boolean(token)
      auditEntry(state, user, { action: 'admin.update.settings', target: 'updates', request: { ...rest, github_repository: repo, github_token: token === undefined ? undefined : '***' } })
      return { settings: { ...settings(), github_repository: u.github_repository, github_token_stored: u.github_token_stored } }
    },
    'POST /admin/updates/plan': ({ body, user }) => {
      advance()
      if (u.rollout && ROLLOUT_STATES_ACTIVE.has(u.rollout.state)) throw new Problem(409, 'conflict', 'a rollout is active: resume, cancel or roll it back first')
      const kind = body.kind || 'pelagos'
      if (!['pelagos', 'engine_packages', 'rollback'].includes(kind)) throw invalid('kind', 'pelagos, engine_packages or rollback')
      const all = state.nodes.map((n) => n.peer.id)
      let version = body.version ?? null
      let rel = null
      let ids = all
      let packages = {}
      if (kind === 'pelagos') {
        rel = u.releases.find((r) => r.version === version)
        if (!rel) throw invalid('version', `no available release ${version}`)
        ids = all.filter((id) => compareVersions(state.nodes.find((n) => n.peer.id === id).version, version) < 0)
        if (!ids.length) throw invalid('version', `every node already runs ${version} or newer`)
        if (rel.signature === 'unsigned' || rel.signature === 'unknown_key') {
          if (body.accept_unsigned !== true || body.confirm_version !== version) {
            throw new Problem(400, 'validation_error', `release ${version} is not signed`, [{ field: 'accept_unsigned', message: `release ${version} is not signed: accept the unsigned release and type its version to go on`, message_message: msg('update.refused.unsigned_not_accepted', { version }) }])
          }
        }
      } else if (kind === 'rollback') {
        ids = all.filter((id) => u.previous[id])
        if (!ids.length) throw new Problem(409, 'conflict', 'no node keeps a previous package')
        version = u.previous[ids[0]]
      } else {
        const wanted = body.packages?.length ? body.packages : [...new Set(engines().filter((e) => e.candidate).map((e) => e.package))]
        const known = engines().filter((e) => e.candidate && wanted.includes(e.package))
        if (!known.length) throw invalid('packages', 'no package of the list has a candidate')
        packages = Object.fromEntries(known.map((e) => [e.package, e.candidate]))
      }
      if (body.node_ids?.length) ids = ids.filter((id) => body.node_ids.includes(id))
      const order = body.order?.length ? body.order : defaultOrder(ids)
      if (order.length !== ids.length || !order.every((id) => ids.includes(id))) throw invalid('order', 'every node to update, each once')
      const names = order.map(nameOf)
      const unsigned = rel && rel.signature !== 'valid'
      const autoRollback = body.auto_rollback ?? settings().auto_rollback_enabled ?? true
      const summaryMessage = kind === 'engine_packages'
        ? msg('plan.update.engine_packages', { packages: Object.keys(packages), nodes: names })
        : msg(`plan.update.${kind}`, { version, nodes: names })
      const summary = kind === 'engine_packages'
        ? `update ${Object.keys(packages).join(', ')} on ${names.join(', ')}, in this order`
        : kind === 'rollback' ? `go back to Pelagos ${version} on ${names.join(', ')}, in this order` : `update Pelagos to ${version} on ${names.join(', ')}, in this order`
      const plan = createPlan(state, user, {
        scope: 'update', engine: null, summary, summary_message: summaryMessage, requires_confirmation: true, targets: order,
        tool: 'update_verify',
        changes: order.map((id) => ({ op: 'replace', target: kind === 'engine_packages' ? `node/${id}/packages` : `node/${id}/pelagos`, before: kind === 'engine_packages' ? null : state.nodes.find((n) => n.peer.id === id).version, after: kind === 'engine_packages' ? packages : version, node_ids: [id] })),
        apply: () => {
          if (unsigned) auditEntry(state, user, { action: 'update.unsigned_accepted', target: `release:${version}`, request: { version, signature: rel.signature, key_id: rel.key_id } })
          u.rollout = rolloutOf(kind, kind === 'engine_packages' ? null : version, order, {
            created_by: user.username, source: rel?.source || null, packages, auto_rollback: autoRollback, signature: rel?.signature || 'valid', key_id: rel?.key_id || null,
            unsigned_accepted_by: unsigned ? user.username : null, unsigned_accepted_at: unsigned ? iso(Date.now()) : null,
            artifacts: rel ? { 'deb/amd64': { file: `pelagos_${version}-1_amd64.deb`, sha256: 'a'.repeat(64) }, 'deb/arm64': { file: `pelagos_${version}-1_arm64.deb`, sha256: 'b'.repeat(64) } } : {},
          })
          return `rollout ${u.rollout.id} written to updates.rollout`
        },
      })
      plan.update = {
        kind, version, order, packages, signature: rel?.signature || 'valid', key_id: rel?.key_id || null,
        unsigned_warning: unsigned ? msg('plan.update.unsigned', { version }) : null,
        state_schema_changed: false, auto_rollback: autoRollback,
        checks: kind === 'engine_packages' ? ['precheck', 'ha_maintenance', 'version', 'engine_checks', 'ha'] : ['precheck', 'backup', 'version', 'health', 'convergence', 'audit', 'journal', 'ha'],
        estimated_seconds: order.length * ((settings().settle_seconds ?? 30) + 90) + (order.length - 1) * (settings().pause_seconds ?? 60),
        requires_password: true,
      }
      auditEntry(state, user, { action: 'admin.update.plan', target: 'updates', plan_id: plan.id, request: { kind, version, order, packages } })
      return plan
    },
    'GET /admin/updates/rollout': () => {
      advance()
      return u.rollout
    },
    'POST /admin/updates/rollout/{id}/action': ({ params, body, user }) => {
      advance()
      const r = u.rollout
      if (!r || r.id !== params.id) throw new Problem(404, 'not_found', `no rollout ${params.id}`)
      const action = body.action
      if (!['resume', 'cancel', 'rollback'].includes(action)) throw invalid('action', 'resume, cancel or rollback')
      if (action === 'resume') {
        if (r.state !== 'failed') throw new Problem(409, 'conflict', `the rollout is ${r.state}`)
        for (const n of r.nodes) if (['failed', 'rolled_back'].includes(n.state)) Object.assign(n, { state: 'pending', step: null, error: null, error_message: null, started_at: null, finished_at: null, to_version: r.version })
        const rel = u.releases.find((x) => x.version === r.version)
        if (rel) rel.broken = false
        r.state = 'running'
      } else if (action === 'cancel') {
        if (!ROLLOUT_STATES_ACTIVE.has(r.state)) throw new Problem(409, 'conflict', `the rollout is ${r.state}`)
        for (const n of r.nodes) if (['pending', 'running'].includes(n.state)) n.state = 'skipped'
        finish(r, 'cancelled')
      } else {
        requirePassword(user, body.password)
        const done = r.nodes.filter((n) => n.state === 'done').map((n) => n.node_id).reverse()
        if (!done.length) throw new Problem(409, 'conflict', 'no node was updated: nothing to roll back')
        if (ROLLOUT_STATES_ACTIVE.has(r.state)) finish(r, 'cancelled')
        u.rollout = rolloutOf('rollback', r.nodes.find((n) => n.state === 'done').from_version, done, { created_by: user.username })
      }
      auditEntry(state, user, { action: `admin.update.${action}`, target: `update:${r.id}`, request: { action } })
      advance()
      return u.rollout
    },
    'GET /admin/updates/history': ({ query }) => {
      advance()
      const page = Number(query.get('page') || 1)
      const per = Math.min(Number(query.get('per_page') || 50), 500)
      return { items: u.history.slice((page - 1) * per, page * per), page, per_page: per, total: u.history.length, meta: {} }
    },
  }
}

