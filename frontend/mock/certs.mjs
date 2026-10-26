// SPDX-License-Identifier: Apache-2.0
// Web UI certificates of the mock (services/cert_service.py): per node state, the cluster
// source, checks of uploaded PEM text, issuance jobs that finish after a short delay.
import { iso, ulid } from './data.mjs'
import { auditEntry } from './plans.mjs'

const DAY = 86400000
const SECRETS = ['eab_hmac', 'dns_api_token', 'ucm_api_key']

function certInfo(name, { issuer = name, days = 3650, ageDays = 30, selfSigned = true, san = [name, 'localhost'] } = {}) {
  const start = Date.now() - ageDays * DAY
  return {
    subject: `CN=${name}`,
    issuer: `CN=${issuer}`,
    common_name: name,
    issuer_common_name: issuer,
    serial: Math.floor(Math.random() * 1e12).toString(16),
    not_before: iso(start),
    not_after: iso(start + days * DAY),
    san,
    fingerprint: `sha256:${Array.from({ length: 64 }, () => Math.floor(Math.random() * 16).toString(16)).join('')}`,
    key_type: 'ec-secp256r1',
    self_signed: selfSigned,
  }
}

export function makeCerts(nodes) {
  const out = {}
  for (const node of nodes) {
    const host = new URL(node.peer.web_url).hostname
    out[node.peer.id] = {
      current: certInfo(host, { san: [host, node.peer.name, 'localhost'] }),
      source: { source: 'self_signed' },
      last_issued_at: null,
      last_source: 'self_signed',
      failures: 0,
      last_error: null,
      next_attempt_at: null,
      job: null,
      log: [],
      pending_request: null,
      secrets: {},
    }
  }
  return out
}

export function certsHandlers(state, { Problem, invalid }) {
  const thresholds = () => ({
    warning_days: state.settings.alerts_cert_warning_days ?? 30,
    critical_days: state.settings.alerts_cert_critical_days ?? 7,
  })
  state.certs ||= {}
  state.certCluster ??= null
  state.certClusterSecrets ||= {}
  // A node's entry is made the first time it is seen (nodes enrolled later included).
  const nodeOf = (id) => {
    const node = state.nodes.find((n) => n.peer.id === id)
    if (!node) throw new Problem(404, 'not_found', `node ${id} not found`)
    if (!state.certs[id]) Object.assign(state.certs, makeCerts([node]))
    return node
  }
  const effective = (id) => {
    const own = state.certs[id].source
    const cluster = state.certCluster
    if ((!own || own.source === 'inherit') && cluster && (cluster.node_ids === 'all' || cluster.node_ids.includes(id))) {
      return { source: cluster, inherited: true, scope: 'cluster' }
    }
    return { source: own?.source === 'inherit' ? { source: 'self_signed' } : own, inherited: false, scope: `node-${id}` }
  }
  const publicSource = (src, scope) => ({
    ...src,
    secrets: Object.fromEntries(SECRETS.map((k) => [k, Boolean((scope === 'cluster' ? state.certClusterSecrets : state.certs[scope.slice(5)]?.secrets)?.[k])])),
  })
  const names = (node, src) => {
    const host = new URL(node.peer.web_url).hostname
    if (src?.mode === 'cluster' && src.cluster_name) return [src.cluster_name, ...(src.names || [])]
    const all = [host, node.peer.name, ...(src?.names || [])]
    return src?.source === 'acme' ? all.filter((n) => n.includes('.')) : all
  }
  const status = (id) => {
    const node = nodeOf(id)
    const c = state.certs[id]
    const eff = effective(id)
    const automatic = ['acme', 'ucm'].includes(eff.source?.source)
    const end = Date.parse(c.current.not_after)
    const start = Date.parse(c.current.not_before)
    return {
      node_id: id,
      name: node.peer.name,
      web_url: node.peer.web_url,
      current: c.current,
      chain: [],
      source: publicSource(eff.source || { source: 'self_signed' }, eff.scope),
      inherited: eff.inherited,
      cluster_applies: Boolean(state.certCluster && (state.certCluster.node_ids === 'all' || state.certCluster.node_ids.includes(id))),
      names: names(node, eff.source),
      required_names: [new URL(node.peer.web_url).hostname],
      last_issued_at: c.last_issued_at,
      last_source: c.last_source,
      next_renewal_at: automatic ? iso(end - (end - start) / 3) : null,
      failures: c.failures,
      next_attempt_at: c.next_attempt_at,
      last_error: c.last_error,
      job: c.job,
      log: [...c.log].reverse(),
      pending_request: c.pending_request,
      files: { cert: '/etc/pelagos/tls/server.crt', key: '/etc/pelagos/tls/server.key' },
    }
  }
  const note = (id, message, level = 'info') => state.certs[id].log.push({ ts: iso(Date.now()), level, message })
  const issue = (id, user) => {
    const node = nodeOf(id)
    const c = state.certs[id]
    const src = effective(id).source
    const host = new URL(node.peer.web_url).hostname
    // A node named in failNodes fails, like a node whose DNS provider refuses the token.
    if ((state.certFailNodes || []).includes(node.peer.name)) {
      c.failures += 1
      c.last_error = 'ACME: TXT _acme-challenge.' + host + ' not visible on 192.0.2.53 after 180 s'
      c.next_attempt_at = iso(Date.now() + 300000)
      note(id, c.last_error, 'error')
      return { ok: false, error: c.last_error }
    }
    const issuer = src.source === 'ucm' ? 'UCM Lab Issuing CA' : src.acme?.profile?.startsWith('letsencrypt') ? 'R11' : 'Lab ACME Intermediate'
    c.current = certInfo(host, { issuer, days: src.source === 'ucm' ? 365 : src.acme?.profile === 'private' ? 1 : 90, ageDays: 0, selfSigned: false, san: names(node, src) })
    c.last_issued_at = iso(Date.now())
    c.last_source = src.source
    c.failures = 0
    c.last_error = null
    c.next_attempt_at = null
    note(id, `installed ${src.source} certificate ${c.current.fingerprint.slice(0, 23)}`)
    auditEntry(state, user, { action: 'admin.cert.apply', target: `cert:web:${node.peer.name}`, request: { op: 'apply', source: src.source, fingerprint: c.current.fingerprint } })
    return { ok: true, certificate: c.current }
  }
  const startJob = (ids, user) => {
    const job = { id: ulid(), plan_id: null, state: 'running', progress: 0, steps: [], created_at: iso(Date.now()), finished_at: null, error: null }
    state.jobs.set(job.id, job)
    let i = 0
    const tick = () => {
      if (i >= ids.length) {
        const failed = job.steps.filter((s) => s.state === 'failed')
        job.state = failed.length ? 'failed' : 'done'
        job.error = failed.length ? `ServiceError: certificate not renewed on ${failed.map((s) => s.label).join(', ')}` : null
        job.progress = 100
        job.finished_at = iso(Date.now())
        return
      }
      const id = ids[i]
      const name = nodeOf(id).peer.name
      const out = issue(id, user)
      job.steps.push({ name: `cert/${id}`, label: `certificate of ${name}`, label_message: { key: 'job.step.cert_node', params: { node: name } }, node_id: id, state: out.ok ? 'done' : 'failed', output: out.ok ? { certificate: out.certificate } : out.error, started_at: iso(Date.now()), finished_at: iso(Date.now()) })
      i += 1
      job.progress = Math.round((i / ids.length) * 100)
      const timer = setTimeout(tick, state.jobStepMs ?? 400)
      timer.unref?.()
    }
    const timer = setTimeout(tick, 50)
    timer.unref?.()
    return job
  }
  const storeSecrets = (holder, body) => {
    for (const [k, v] of Object.entries(body.secrets || {})) {
      if (!SECRETS.includes(k)) continue
      if (v) holder[k] = true
      else delete holder[k]
    }
  }
  const validate = (body, cluster) => {
    const allowed = cluster ? ['acme', 'ucm'] : ['self_signed', 'manual', 'acme', 'ucm', 'inherit']
    if (!allowed.includes(body.source)) throw invalid('source', `source must be one of ${allowed.join(', ')}`)
    if (body.source === 'ucm' && !String(body.ucm?.url || '').startsWith('https://')) throw invalid('ucm.url', 'the UCM URL must start with https://')
    if (body.source === 'acme' && ['private', 'custom'].includes(body.acme?.profile) && !String(body.acme?.directory_url || '').startsWith('https://')) {
      throw invalid('acme.directory_url', 'the ACME directory URL must start with https://')
    }
  }
  const strip = (body) => {
    const { secrets: _s, apply: _a, ...rest } = body
    return rest
  }

  return {
    'GET /admin/certificates': () => ({
      nodes: state.nodes.map((n) => ({ ...status(n.peer.id), reachable: true, is_self: n.peer.id === state.selfId })),
      cluster: state.certCluster ? publicSource(state.certCluster, 'cluster') : null,
      settings: { ucm_renew_days: 30, retry_min_seconds: 300, retry_max_seconds: 21600, propagation_seconds: 180 },
      thresholds: thresholds(),
      providers: [{ type: 'hetzner', label: 'Hetzner DNS', credentials: ['api_token'] }],
      acme_profiles: ['letsencrypt', 'letsencrypt-staging', 'private', 'custom'],
      key_types: ['ec-p256', 'rsa-3072'],
    }),
    'GET /admin/certificates/{id}': ({ params }) => status(params.id),
    'PUT /admin/certificates/cluster': ({ body, user }) => {
      validate(body, true)
      state.certCluster = { ...strip(body), node_ids: body.node_ids || 'all', revision: ulid() }
      storeSecrets(state.certClusterSecrets, body)
      const targets = state.certCluster.node_ids === 'all' ? state.nodes.map((n) => n.peer.id) : state.certCluster.node_ids
      for (const id of targets) if (state.certs[id]) state.certs[id].source = { source: 'inherit' }
      auditEntry(state, user, { action: 'admin.cert.replace', target: 'cert:web:cluster' })
      const job = body.apply === false ? null : startJob(targets, user)
      return { cluster: publicSource(state.certCluster, 'cluster'), job }
    },
    'DELETE /admin/certificates/cluster': ({ user }) => {
      state.certCluster = null
      state.certClusterSecrets = {}
      auditEntry(state, user, { action: 'admin.cert.delete', target: 'cert:web:cluster' })
      return null
    },
    'PUT /admin/certificates/{id}/source': ({ params, body, user }) => {
      nodeOf(params.id)
      validate(body, false)
      const c = state.certs[params.id]
      c.source = { ...strip(body), revision: ulid() }
      storeSecrets(c.secrets, body)
      auditEntry(state, user, { action: 'admin.cert.replace', target: `cert:web:${nodeOf(params.id).peer.name}` })
      const job = body.apply && ['acme', 'ucm'].includes(body.source) ? startJob([params.id], user) : null
      return { source: publicSource(c.source, `node-${params.id}`), job }
    },
    'POST /admin/certificates/{id}/renew': ({ params, user, res }) => {
      nodeOf(params.id)
      const job = startJob([params.id], user)
      if (res) res.statusCode = 202
      return job
    },
    'POST /admin/certificates/{id}/request': ({ params, body, user }) => {
      const node = nodeOf(params.id)
      const host = new URL(node.peer.web_url).hostname
      const names = [host, node.peer.name, ...(body.names || [])]
      const pending = {
        csr_pem: `-----BEGIN CERTIFICATE REQUEST-----\nMIIBmock${node.peer.name}\n-----END CERTIFICATE REQUEST-----\n`,
        names,
        key_type: body.key_type || 'ec-p256',
        created_at: iso(Date.now()),
      }
      state.certs[params.id].pending_request = pending
      auditEntry(state, user, { action: 'admin.cert.add', target: `cert:web:${node.peer.name}`, request: { op: 'request', names } })
      return pending
    },
    'DELETE /admin/certificates/{id}/request': ({ params }) => {
      nodeOf(params.id)
      state.certs[params.id].pending_request = null
      return null
    },
    'POST /admin/certificates/{id}/check': ({ params, body }) => checkReport(nodeOf(params.id), state.certs[params.id], body),
    'POST /admin/certificates/{id}/upload': ({ params, body, user }) => {
      const node = nodeOf(params.id)
      const c = state.certs[params.id]
      const report = checkReport(node, c, body)
      if (!report.ok) {
        const problem = new Problem(400, 'validation_error', 'the certificate did not pass the checks')
        problem.extra = { checks: report }
        throw problem
      }
      c.current = report.certificate
      c.source = { source: 'manual' }
      c.last_issued_at = iso(Date.now())
      c.last_source = 'manual'
      if (body.use_pending_key) c.pending_request = null
      note(params.id, `installed manual certificate ${c.current.fingerprint.slice(0, 23)}`)
      auditEntry(state, user, { action: 'admin.cert.apply', target: `cert:web:${node.peer.name}`, request: { op: 'upload', fingerprint: c.current.fingerprint } })
      const also = {}
      for (const other of body.also_node_ids || []) {
        const peer = nodeOf(other)
        state.certs[other].current = { ...report.certificate }
        state.certs[other].source = { source: 'manual' }
        also[peer.peer.name] = 'sent: the node installs it within a minute'
      }
      return { fingerprint: c.current.fingerprint, certificate: c.current, notes: [], checks: report, ...(Object.keys(also).length ? { also } : {}) }
    },
    'POST /admin/certificates/{id}/self-signed': ({ params, user }) => {
      const node = nodeOf(params.id)
      const host = new URL(node.peer.web_url).hostname
      const c = state.certs[params.id]
      c.current = certInfo(host, { ageDays: 0, san: [host, node.peer.name, 'localhost'] })
      c.source = { source: 'self_signed' }
      c.last_issued_at = iso(Date.now())
      c.last_source = 'self_signed'
      auditEntry(state, user, { action: 'admin.cert.apply', target: `cert:web:${node.peer.name}`, request: { op: 'self_signed' } })
      return { fingerprint: c.current.fingerprint, certificate: c.current, notes: [] }
    },
    'POST /admin/certificates/test/ucm': ({ body }) => {
      if (!String(body.ucm?.url || '').startsWith('https://')) return { ok: false, error: 'the UCM URL must start with https://' }
      return {
        ok: true,
        cas: [{ id: 3, name: 'Lab Issuing CA', status: 'Active', can_sign: true }, { id: 4, name: 'Lab Root CA', status: 'Active', can_sign: true }],
        templates: [{ id: 7, name: 'Web server', type: 'server' }],
      }
    },
    'POST /admin/certificates/test/acme': ({ body }) => {
      const profile = body.acme?.profile || 'letsencrypt-staging'
      const url = { letsencrypt: 'https://acme-v02.api.letsencrypt.org/directory', 'letsencrypt-staging': 'https://acme-staging-v02.api.letsencrypt.org/directory' }[profile] || body.acme?.directory_url
      if (!url) return { ok: false, error: 'not an HTTP URL' }
      return { ok: true, directory_url: url, eab_required: false, terms: null }
    },
    'POST /admin/certificates/test/dns': ({ body }) => (body.dns?.provider === 'hetzner' ? { ok: true, detail: '2 zones: example.lan, example.net' } : { ok: false, error: `unknown DNS provider ${body.dns?.provider}` }),
    'POST /admin/certificates/dns01/plan': () => ({
      key: 'ddi-acme',
      challenge_names: state.nodes.map((n) => `_acme-challenge.${new URL(n.peer.web_url).hostname}.`),
      unserved: [],
      manual: [{ zone: 'example.lan.', view: '_default', statements: state.nodes.map((n) => `grant ddi-acme name _acme-challenge.${new URL(n.peer.web_url).hostname}. TXT;`) }],
      delegation: [],
      plan: null,
    }),
  }
}

// Checks of the mock: the PEM must hold a certificate; "expired" or a missing key fail.
function checkReport(node, c, body) {
  const host = new URL(node.peer.web_url).hostname
  const text = String(body.cert_pem || '')
  const p12 = Boolean(body.pkcs12_base64)
  const checks = []
  const hasCert = p12 || text.includes('BEGIN CERTIFICATE')
  if (!hasCert) return { ok: false, checks: [{ id: 'certificate', code: 'certificate.none', level: 'error', message: 'no certificate found', params: {} }], certificate: null, chain: [] }
  const hasKey = p12 || Boolean(body.key_pem) || (body.use_pending_key && c.pending_request)
  checks.push(hasKey ? { id: 'key', code: 'key.ok', level: 'ok', message: 'the private key matches the certificate', params: {} } : { id: 'key', code: 'key.missing', level: 'error', message: 'no private key: give the key or use a request made here', params: {} })
  const expired = text.includes('EXPIRED')
  checks.push(expired ? { id: 'dates', code: 'dates.expired', level: 'error', message: 'the certificate has expired', params: {} } : { id: 'dates', code: 'dates.ok', level: 'ok', message: 'the certificate is valid', params: {} })
  checks.push({ id: 'names', code: 'names.ok', level: 'ok', message: 'the certificate covers {names}', params: { names: [host] } })
  checks.push({ id: 'usage', code: 'usage.ok', level: 'ok', message: 'the certificate allows server authentication', params: {} })
  checks.push(body.chain_pem || p12 ? { id: 'chain', code: 'chain.ok', level: 'ok', message: 'the chain is complete and in order', params: {} } : { id: 'chain', code: 'chain.reordered', level: 'warning', message: 'the chain was given out of order: it is installed in order', params: {} })
  checks.push({ id: 'trust', code: 'trust.unknown', level: 'warning', message: 'the issuer is not recognized by the system', params: {} })
  const certificate = certInfo(host, { issuer: 'Example Corp Issuing CA', days: 365, ageDays: 1, selfSigned: false, san: [host, node.peer.name] })
  return { ok: checks.every((x) => x.level !== 'error'), checks, certificate, chain: [] }
}
