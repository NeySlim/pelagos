// SPDX-License-Identifier: Apache-2.0
// Mock Pelagos API: every endpoint of docs/architecture.md section 17 plus the
// WebSocket of section 18, in memory, with sessions, CSRF, RBAC, RFC 7807
// errors, pagination and the plan lifecycle. `npm run mock` starts it on
// 127.0.0.1:8481 (or --port N); Vite proxies /api to it when VITE_API_MOCK=1.
// Users: admin/admin, alice/alice (dns-operator), bob/bob + TOTP 123456
// (dhcp-operator), viewer/viewer.
import http from 'node:http'
import { randomBytes, createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { ENDPOINTS } from '../src/services/endpoints.js'
import { EXCEPTABLE_KINDS, INCONSISTENCY_KINDS } from '../src/pages/alerts/kinds.js'
import { passwordProblem } from '../src/lib/password.js'
import { createState, iso, ulid, ALL_PERMISSIONS, SCENARIOS } from './data.mjs'
import { createPlan, applyPlan, rollbackPlan, unifiedDiff, jsonText, rrsetText, isExpired, auditEntry, configHash, isAdmin } from './plans.mjs'
import { createWsHub } from './ws.mjs'
import { opsHandlers } from './ops.mjs'
import { rpzHandlers } from './rpz.mjs'
import { ptrHelpers } from './ptr.mjs'
import { certsHandlers } from './certs.mjs'
import { notifyHandlers } from './notify.mjs'
import { archivesHandlers } from './archives.mjs'
import { ddnsFailoverHandlers } from './ddnsFailover.mjs'
import { resolverHandlers } from './resolver.mjs'
import { keaMigrationHandlers } from './keaMigration.mjs'
import { ipv6Handlers } from './ipv6.mjs'
import { SETTINGS_SCHEMA, setting, updateSettings } from './settings.mjs'
import { heartbeatAge, liveCounters } from './live.mjs'
import { createEvents, leaseBrief, poolHistoryKey, stopEventTimers, zoneEvents } from './events.mjs'

const API = '/api/v1'
const ANON = new Set(['GET /health', 'GET /version', 'POST /auth/login'])
const LOGIN_MAX_FAILURES = 5
const LOGIN_WINDOW_MS = 60_000

// Permission of each endpoint (section 17); undefined means any authenticated user.
const PERMISSIONS = {
  'GET /nodes': 'read:nodes', 'GET /nodes/self': 'read:nodes', 'GET /nodes/{id}': 'read:nodes',
  'POST /nodes/enroll-token': 'admin:nodes', 'DELETE /nodes/{id}': 'admin:nodes', 'POST /nodes/{id}/sync': 'admin:nodes',
  'GET /nodes/replication': 'read:nodes',
  'GET /dns/instances': 'read:dns', 'GET /dns/zones': 'read:dns', 'GET /dns/zones/{zone}': 'read:dns',
  'POST /dns/zones/plan': 'write:dns.zones', 'GET /dns/zones/{zone}/records': 'read:dns',
  'POST /dns/zones/{zone}/records/plan': 'write:dns.records', 'POST /dns/zones/{zone}/retransfer': 'ops:dns',
  'POST /dns/zones/{zone}/notify': 'ops:dns', 'POST /dns/zones/{zone}/reload': 'ops:dns',
  'GET /dns/zones/{zone}/dnssec': 'read:dns', 'GET /dns/config': 'read:dns', 'GET /dns/handover': 'read:dns', 'POST /dns/config/plan': 'write:dns.config',
  'GET /dns/keys': 'read:dns', 'GET /dns/keys/{name}/secret': 'read:dns.secrets', 'POST /dns/keys/plan': 'write:dns.config',
  'GET /dns/acls': 'read:dns', 'POST /dns/acls/plan': 'write:dns.config', 'GET /dns/resolver': 'read:dns',
  'POST /dns/resolver/plan': 'write:dns.config', 'GET /dns/rpz': 'read:dns', 'GET /dns/catalog-zones': 'read:dns',
  'GET /dns/rpz/overview': 'read:dns', 'GET /dns/rpz/catalog': 'read:dns', 'PUT /dns/rpz/categories/{category}': 'write:dns.config',
  'DELETE /dns/rpz/categories/{category}': 'write:dns.config', 'PUT /dns/rpz/subscriptions/{id}': 'write:dns.config',
  'DELETE /dns/rpz/subscriptions/{id}': 'write:dns.config', 'PUT /dns/rpz/order': 'write:dns.config', 'POST /dns/rpz/plan': 'write:dns.config',
  'POST /dns/rpz/estimate': 'read:dns', 'POST /dns/rpz/refresh': 'write:dns.config', 'GET /dns/rpz/why': 'read:dns',
  'GET /dns/rpz/activity': 'read:dns', 'POST /dns/rpz/allow': 'write:dns.config', 'DELETE /dns/rpz/allow': 'write:dns.config',
  'POST /dns/rpz/exempt': 'write:dns.config', 'DELETE /dns/rpz/exempt': 'write:dns.config',
  'GET /dns/stats': 'read:dns', 'POST /dns/catalog-zones/{zone}/members/plan': 'write:dns.records',
  'GET /dns/dnssec/policies': 'read:dns', 'POST /dns/dnssec/policies/plan': 'write:dns.config',
  'POST /dns/zones/{zone}/dnssec/plan': 'write:dns.zones',
  'POST /dhcp/{family}/subnets/plan': 'write:dhcp.subnets', 'POST /dhcp/{family}/shared-networks/plan': 'write:dhcp.subnets',
  'POST /dhcp/{family}/client-classes/plan': 'write:dhcp.classes', 'POST /dhcp/{family}/options/plan': 'write:dhcp.options',
  'POST /dhcp/{family}/reservations/plan': 'write:dhcp.reservations', 'POST /dhcp/{family}/leases/{ip}/delete/plan': 'ops:dhcp.leases',
  'POST /dhcp/{family}/ha/maintenance/plan': 'ops:dhcp.ha', 'POST /dhcp/{family}/service/plan': 'ops:dhcp.ha',
  'POST /dhcp/{family}/ha/repair/plan': 'ops:dhcp.ha',
  'POST /dhcp/{family}/ha/setup/plan': 'write:dhcp.config', 'POST /dns/zones/{zone}/secondaries/plan': 'write:dns.zones',
  'POST /dhcp/{family}/ddns/plan': 'write:dhcp.options', 'POST /dhcp/{family}/hooks/plan': 'write:dhcp.config',
  'POST /dhcp/{family}/config/plan': 'write:dhcp.config', 'POST /dhcp/d2/config/plan': 'write:dhcp.config',
  'POST /dhcp/{family}/config/adopt/plan': 'write:dhcp.config', 'POST /dhcp/d2/config/adopt/plan': 'write:dhcp.config',
  'GET /hosts': 'read:hosts', 'GET /hosts/{key}': 'read:hosts', 'POST /hosts/plan': 'write:hosts',
  'GET /alerts': 'read:alerts', 'GET /alerts/summary': 'read:alerts', 'POST /alerts/{id}/ack': 'write:alerts',
  'POST /alerts/consistency/run': 'write:alerts',
  'GET /alerts/exceptions': 'read:alerts', 'POST /alerts/exceptions': 'write:alerts', 'DELETE /alerts/exceptions/{id}': 'write:alerts',
  'POST /dns/ptr/coverage': 'read:dns', 'GET /dns/ptr/orphans': 'read:dns', 'POST /dns/ptr/orphans/plan': 'write:dns.records',
  'GET /series/pools': 'read:series', 'GET /series/serials': 'read:series', 'GET /series/ha-transitions': 'read:series',
  'GET /audit': 'read:audit', 'GET /audit/{id}': 'read:audit', 'GET /audit/export': 'read:audit',
  'GET /advanced/bind/grammar': 'read:advanced', 'GET /advanced/bind/tree': 'read:advanced',
  'GET /advanced/kea/{family}/schema': 'read:advanced', 'GET /advanced/history': 'read:advanced',
  'GET /advanced/history/{id}': 'read:advanced',
  'GET /install/detect': 'admin:install', 'POST /install/plan': 'admin:install', 'POST /install/import/plan': 'admin:install',
  'GET /install/security': 'admin:install', 'POST /install/security/plan': 'admin:install',
  'GET /install/security/ha-guard': 'admin:install', 'POST /install/security/ha-guard/plan': 'admin:install',
  'POST /install/security/ha-tls/plan': 'admin:install',
  'GET /admin/users': 'admin:users', 'POST /admin/users': 'admin:users', 'GET /admin/users/{id}': 'admin:users',
  'PUT /admin/users/{id}': 'admin:users', 'DELETE /admin/users/{id}': 'admin:users',
  'POST /admin/users/{id}/reset-password': 'admin:users', 'DELETE /admin/users/{id}/totp': 'admin:users',
  'GET /admin/roles': 'admin:roles', 'POST /admin/roles': 'admin:roles', 'PUT /admin/roles/{name}': 'admin:roles',
  'DELETE /admin/roles/{name}': 'admin:roles', 'GET /admin/permissions': 'admin:roles',
  'GET /admin/settings': 'admin:settings', 'PUT /admin/settings': 'admin:settings', 'GET /admin/settings/schema': 'admin:settings',
  'GET /admin/modules': 'admin:modules', 'PUT /admin/modules': 'admin:modules',
  'GET /dns/ops': 'read:dns',
}
for (const spec of ENDPOINTS) {
  if (spec.includes(' /dhcp/') && spec.startsWith('GET ') && !PERMISSIONS[spec]) PERMISSIONS[spec] = 'read:dhcp'
  if (spec.includes(' /admin/certificates')) PERMISSIONS[spec] = 'admin:certificates'
  if (spec.includes(' /admin/notifications')) PERMISSIONS[spec] = 'admin:notifications'
  if (spec.includes(' /admin/archives')) PERMISSIONS[spec] = 'admin:archives'
}
// The DDNS failover endpoints need two permissions: the first here, the second in the handler.
Object.assign(PERMISSIONS, {
  'GET /dhcp/ddns/resilience': 'read:dhcp', 'POST /dhcp/ddns/resilience/plan': 'write:dns.zones',
  'POST /dhcp/ddns/failover/plan': 'write:dns.zones', 'POST /dhcp/ddns/switchover/plan': 'write:dns.zones',
  'POST /dhcp/ddns/replay/plan': 'ops:dhcp.leases',
  'GET /dns/resolver/health': 'read:dns', 'GET /series/resolver': 'read:series',
  'POST /dns/resolver/fallback/plan': 'write:dns.config', 'POST /dns/resolver/fallback/return/plan': 'write:dns.config',
  'PUT /dns/resolver/fallback': 'write:dns.config',
  'GET /install/kea-migration': 'admin:install', 'POST /install/kea-migration/analyze': 'admin:install',
  'GET /hosts/ipv6': 'read:hosts', 'GET /admin/ipv6': 'admin:settings', 'PUT /admin/ipv6': 'admin:settings',
  'POST /admin/ipv6/sources/test': 'admin:settings',
})

class Problem extends Error {
  constructor(status, code, detail, errors) {
    super(detail)
    this.status = status
    this.code = code
    this.errors = errors
  }
}
const notFound = (what) => new Problem(404, 'not_found', `${what} not found`)

// Section 9: a diverged Kea file blocks configuration plans of that engine (409 config_divergence).
function fileStatus(state, engine) {
  const f = state.keaFiles[engine]
  return { node_id: state.selfId, path: f.path, readable: true, files: [f.path], includes: false, diverged: f.diverged, differences: f.differences, count: f.differences.length, alert_id: null }
}
function assertFileAgrees(state, engine) {
  const f = state.keaFiles[engine]
  if (f?.diverged) {
    throw new Problem(409, 'config_divergence', `the ${engine === 'd2' ? 'd2' : `kea${engine.slice(1)}`} configuration file (${f.path}) differs from the running configuration on ns1: adopt the file or the running configuration first`)
  }
}
function adoptPlan(state, user, engine, body) {
  if (!['file', 'running'].includes(body.source)) throw invalid('source', 'file or running')
  const f = state.keaFiles[engine]
  const before = { ...f, differences: [...f.differences] }
  const daemon = engine === 'd2' ? 'd2' : `kea${engine.slice(1)}`
  const diff = body.source === 'file'
    ? `--- running (${daemon} config-get)\n+++ ${f.path}\n${f.differences.map((d) => `~ ${d}`).join('\n')}\n`
    : unifiedDiff('"algorithm": "HMAC-SHA256"', '"algorithm": "HMAC-MD5"', f.path)
  return createPlan(state, user, {
    scope: engine === 'd2' ? 'd2.config' : 'dhcp.config',
    engine: daemon,
    summary: body.source === 'file' ? `${daemon}: adopt ${f.path} as the running configuration` : `${daemon}: write the running configuration to ${f.path}`,
    changes: [{ op: 'replace', target: `adopt/${body.source}`, before: { files: [f.path], differences: f.differences }, after: { source: body.source }, node_ids: [] }],
    diff,
    targets: [body.node_id || state.selfId],
    tool: body.source === 'file' ? 'config-test' : 'lossless-editor',
    requires_confirmation: true,
    apply: () => {
      f.diverged = false
      f.differences = []
      for (const a of state.alerts) if (a.subject === `${daemon}:config-file` && a.state !== 'resolved') a.state = 'resolved'
      return body.source === 'file' ? 'config-test, config-set' : `patched ${f.path}`
    },
    rollback: () => Object.assign(f, before),
  })
}
const invalid = (field, message) => new Problem(400, 'validation_error', 'Invalid request', [{ field, message }])
// Finding ids carry no fixed vocabulary: the dual-key rotation is keyed on kind and engine.
// The shape of installer.security_audit.Finding.to_dict(): ids are <engine>:<kind>:<subject>.
const finding = (engine, kind, subject, severity, texts, remediable = true) => ({
  id: `${engine}:${kind}:${subject}`, kind, severity, engine, subject: texts.subject || subject, remediable,
  description: texts.description, proposal: texts.proposal, risk: texts.risk,
  description_message: texts.description_message || null, proposal_message: texts.proposal_message || null,
  risk_message: texts.risk_message || null,
  manual_action: remediable ? null : texts.proposal, manual_action_message: remediable ? null : texts.proposal_message || null,
})
const SECURITY_FINDINGS = [
  finding('bind', 'weak_rndc_key', 'rndc-key', 'critical', {
    description: 'The rndc key rndc-key uses hmac-md5.',
    description_message: { key: 'finding.weak_rndc_key.description', params: { key: 'rndc-key', algorithm: 'hmac-md5' } },
    proposal: 'Regenerate rndc-key in hmac-sha256 with a new secret and restart named.',
    proposal_message: { key: 'finding.weak_rndc_key.proposal', params: { key: 'rndc-key', new_algorithm: 'hmac-sha256' } },
    risk: 'Other tools using this key (scripts, a remote rndc) stop working until they get the new key.',
    risk_message: { key: 'finding.weak_rndc_key.risk', params: {} },
  }),
  // BIND and D2 on this node: the audit reports the shared key once, from the BIND side.
  finding('bind', 'weak_shared_kea_key', 'ddns-legacy', 'critical', {
    description: 'TSIG key ddns-legacy shared with Kea D2 uses hmac-md5.',
    description_message: { key: 'finding.weak_shared_kea_key.description', params: { key: 'ddns-legacy', algorithm: 'hmac-md5' } },
    proposal: 'Dual-key switch: add ddns-legacy-sha256 (hmac-sha256) to BIND next to the old key, switch D2 on every node, then remove the old key.',
    proposal_message: { key: 'finding.weak_shared_kea_key.proposal', params: { new_key: 'ddns-legacy-sha256', new_algorithm: 'hmac-sha256' } },
    risk: 'During the switch both keys are accepted; DDNS updates keep working on every step.',
    risk_message: { key: 'finding.weak_shared_kea_key.risk', params: {} },
  }),
  // D2 only (the BIND side is on another node): the same kind, reported by the kea engine.
  finding('kea', 'weak_shared_kea_key', 'kea-ddns', 'critical', {
    description: 'D2 signs updates with kea-ddns in hmac-md5.',
    description_message: { key: 'finding.weak_shared_kea_key.d2_description', params: { key: 'kea-ddns', algorithm: 'hmac-md5' } },
    proposal: "Dual-key switch: add kea-ddns-sha256 to the primary's BIND, switch D2, remove the old key.",
    proposal_message: { key: 'finding.weak_shared_kea_key.d2_proposal', params: { new_key: 'kea-ddns-sha256' } },
    risk: 'During the switch both keys are accepted; DDNS updates keep working on every step.',
    risk_message: { key: 'finding.weak_shared_kea_key.risk', params: {} },
  }),
  finding('bind', 'stats_nonlocal', '0.0.0.0', 'warning', {
    subject: 'statistics-channels inet 0.0.0.0',
    description: 'The statistics channel listens on 0.0.0.0 and allows all.',
    description_message: { key: 'finding.stats_nonlocal.description', params: { address: '0.0.0.0', allowed: { key: 'finding.allowed.all', params: {} } } },
    proposal: 'statistics-channels { inet 127.0.0.1 port 8053 allow { 127.0.0.1; }; };',
    risk: 'Remote collectors of the BIND statistics lose access; Pelagos reads them locally.',
    risk_message: { key: 'finding.stats_nonlocal.risk', params: {} },
  }),
  finding('bind', 'open_allow_transfer', '_default/partner.example.', 'warning', {
    description: 'Zone partner.example. allows zone transfers to any client.',
    description_message: { key: 'finding.open_allow_transfer.description_zone', params: { zone: 'partner.example.' } },
    // A configuration snippet: the backend sends no message for it, the UI shows it as is.
    proposal: 'allow-transfer { key ddi-read; };',
    risk: 'Secondaries that transfer by address only must be listed or given a key, or their transfers fail.',
    risk_message: { key: 'finding.open_allow_transfer.risk', params: {} },
  }),
  finding('kea', 'kea_http_socket_plain', 'kea4:192.0.2.1', 'critical', {
    subject: 'kea4 http 192.0.2.1:8000',
    description: 'kea4 exposes its control channel in clear HTTP on 192.0.2.1.',
    description_message: { key: 'finding.kea_http_socket_plain.description', params: { engine: 'kea4', address: '192.0.2.1' } },
    proposal: 'Switch the socket to https with trust-anchor, cert-file, key-file and cert-required, or bind it to 127.0.0.1.',
    proposal_message: { key: 'finding.kea_http_socket_plain.proposal', params: {} },
    risk: 'Remote clients of this socket need certificates.',
    risk_message: { key: 'finding.kea_http_socket_plain.risk', params: {} },
  }, false),
]
const isDualKey = (f) => f?.kind === 'weak_shared_kea_key'
// Findings per node, as each node's audit reports them; peers carry three plain ones.
const PEER_FINDING_KINDS = ['weak_rndc_key', 'stats_nonlocal', 'open_allow_transfer']
const securityByNode = (state) => {
  if (!state.security) {
    state.security = new Map(state.nodes.map((n) => [n.peer.id, n.peer.id === state.selfId
      ? SECURITY_FINDINGS.map((f) => ({ ...f }))
      : SECURITY_FINDINGS.filter((f) => PEER_FINDING_KINDS.includes(f.kind)).map((f) => ({ ...f }))]))
  }
  return state.security
}
const SECURITY_EXCEPTION_KIND = 'security_finding'
const markedFindings = (state, nodeId) => {
  const exceptions = state.ptr.exceptions().filter((e) => e.kind === SECURITY_EXCEPTION_KIND)
  const name = state.nodes.find((n) => n.peer.id === nodeId)?.peer.name || nodeId
  return (securityByNode(state).get(nodeId) || []).map((f) => {
    const keys = [`${nodeId}|${f.id}`, f.id]
    const exception = keys.map((k) => exceptions.find((e) => e.key === k)).find(Boolean) || null
    return { ...f, node_id: nodeId, node_name: name, exception_keys: keys, exception }
  })
}
const PASSWORD_RULE ='must have at least 12 characters and three of: lowercase, uppercase, digits, symbols'
const checkPassword = (field, value) => {
  if (passwordProblem(value)) throw invalid(field, PASSWORD_RULE)
}

const TITLES = {
  validation_error: 'Validation error', invalid_credentials: 'Invalid credentials', totp_required: 'TOTP code required',
  unauthenticated: 'Authentication required', forbidden: 'Forbidden', csrf_failed: 'CSRF check failed',
  not_found: 'Not found', module_disabled: 'Module disabled', method_not_allowed: 'Method not allowed',
  conflict: 'Conflict', precondition_failed: 'Precondition failed', plan_expired: 'Plan expired', plan_state: 'Plan state',
  confirmation_required: 'Confirmation required', rate_limited: 'Too many requests', not_supported: 'Not supported',
  engine_validation_failed: 'Engine validation failed', internal_error: 'Internal error',
}

// ------------------------------------------------------------------ helpers

function routeOf(method, path) {
  const segments = path.split('/').filter(Boolean)
  let best = null
  for (const spec of ENDPOINTS) {
    const [m, p] = spec.split(' ')
    if (m !== method) continue
    const parts = p.split('/').filter(Boolean)
    if (parts.length !== segments.length) continue
    const params = {}
    let placeholders = 0
    let ok = true
    for (let i = 0; i < parts.length; i += 1) {
      const part = parts[i]
      if (part.startsWith('{')) {
        const name = part.slice(1, -1)
        if (name === 'family' && !['v4', 'v6'].includes(segments[i])) {
          ok = false
          break
        }
        try {
          params[name] = decodeURIComponent(segments[i])
        } catch {
          throw new Problem(400, 'validation_error', 'malformed path')
        }
        placeholders += 1
      } else if (part !== segments[i]) {
        ok = false
        break
      }
    }
    // Literal segments win over placeholders (/dhcp/d2/... and /audit/export).
    if (ok && (!best || placeholders < best.placeholders)) best = { spec, params, placeholders }
  }
  return best
}

// The cluster view of GET /alerts: an alert only an unreadable node reports is not listed.
function visibleAlerts(state) {
  const gone = new Set((state.alertsUnavailable || []).map((u) => u.node_id))
  if (!gone.size) return state.alerts
  return state.alerts.filter((a) => !(a.reported_by || []).length || a.reported_by.some((n) => !gone.has(n)))
}

function paginate(items, query, meta = {}) {
  const page = Math.max(1, parseInt(query.get('page') || '1', 10) || 1)
  const perPage = Math.min(500, Math.max(1, parseInt(query.get('per_page') || '50', 10) || 50))
  const sort = query.get('sort')
  let list = items
  if (sort) {
    const dir = query.get('order') === 'desc' ? -1 : 1
    list = [...items].sort((a, b) => dir * String(a[sort] ?? '').localeCompare(String(b[sort] ?? ''), undefined, { numeric: true }))
  }
  return { items: list.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: list.length, meta }
}

const absName = (name) => {
  const lower = String(name || '').toLowerCase()
  return lower.endsWith('.') ? lower : `${lower}.`
}

function ipToInt(ip) {
  return ip.split('.').reduce((acc, part) => acc * 256 + Number(part), 0)
}

function poolRange(pool) {
  if (pool.includes('-')) {
    const [a, b] = pool.split('-').map((s) => s.trim())
    return [a, b]
  }
  const [base, bits] = pool.split('/')
  const start = ipToInt(base)
  const size = 2 ** (32 - Number(bits))
  const toIp = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')
  return [toIp(start), toIp(start + size - 1)]
}

function inPool4(ip, pool) {
  const [a, b] = poolRange(pool)
  const n = ipToInt(ip)
  return n >= ipToInt(a) && n <= ipToInt(b)
}

function poolSize(pool, family) {
  if (family === 'v6') return 4096
  const [a, b] = poolRange(pool)
  return ipToInt(b) - ipToInt(a) + 1
}

function hasPermission(user, permission) {
  if (!permission) return true
  const perms = user.permissions
  return perms.includes('*') || perms.includes(permission)
}

function permissionsOf(state, user) {
  const roles = [...state.builtinRoles, ...state.customRoles]
  const set = new Set()
  for (const name of user.roles) {
    const role = roles.find((r) => r.name === name)
    role?.permissions.forEach((p) => set.add(p))
  }
  return [...set]
}

function publicUser(user, state) {
  const { password: _password, totp: _totp, ...rest } = user
  return { ...rest, preferences: state.preferences.get(user.id) || user.preferences || {} }
}

function nodeName(state, id) {
  return state.nodes.find((n) => n.peer.id === id)?.peer.name || id
}

// ------------------------------------------------------------------ domain reads

// Nodes holding a zone: a Pelagos primary is on this node and on its secondaries (every peer
// until a secondaries plan says otherwise); other zones are on every node.
function zoneHolders(state, zone) {
  const kept = state.secondaries?.[`${zone.view}/${zone.name}`]
  if (zone.kind !== 'primary' || !kept) return state.nodes
  return state.nodes.filter((n) => n.is_self || kept.includes(n.peer.id))
}

function zoneSerials(state, zone) {
  const serial = state.soaSerial(state.records[zone.name])
  const serials = {}
  for (const node of zoneHolders(state, zone)) {
    let value = serial
    if (zone.name === 'lab.example.lan.' && !node.is_self) value = serial - 1
    // Right after a change the secondaries are one serial behind until their IXFR lands.
    else if (!node.is_self && (state.transferLag?.[zone.name] || 0) > Date.now()) value = serial - 1
    if (zone.kind === 'forward') value = null
    serials[node.peer.id] = value
  }
  const values = Object.values(serials).filter((v) => v !== null)
  return { serials, divergent: new Set(values).size > 1 }
}

function zoneStatus(state, zone, nodeId) {
  const { serials } = zoneSerials(state, zone)
  if (!(nodeId in serials) && zone.kind !== 'forward') {
    return { zone: zone.name, view: zone.view, node_id: nodeId, kind: null, serial: null, error: `zone ${zone.name} is not configured on this node`, collected_at: iso(Date.now() - 15000), raw: {} }
  }
  // A Pelagos primary is served by the peers as a secondary of this node.
  const peer = !state.nodes.find((n) => n.peer.id === nodeId)?.is_self
  const kind = peer && zone.kind === 'primary' ? 'secondary' : zone.kind
  return {
    zone: zone.name,
    view: zone.view,
    node_id: nodeId,
    kind,
    serial: serials[nodeId],
    config_serial: serials[nodeId],
    dynamic: zone.dynamic,
    signed: Boolean(zone.dnssec_policy),
    files: zone.file ? [zone.file] : [],
    next_refresh: zone.kind === 'secondary' ? iso(Date.now() + 3200000) : null,
    expires: zone.kind === 'secondary' ? iso(Date.now() + 1209600000) : null,
    last_loaded: iso(Date.now() - 3600000),
    raw: { type: kind, 'files': zone.file || '', 'dynamic': zone.dynamic ? 'yes' : 'no' },
    error: null,
    collected_at: iso(Date.now() - 15000),
  }
}

// How record changes reach a zone (services.dns_extras.zone_mode).
function zoneMode(zone) {
  if (zone.kind === 'primary') return zone.dynamic ? 'dynamic' : 'static'
  return zone.kind
}

function findZone(state, name, view) {
  const zone = state.zones.find((z) => z.name === absName(name) && (!view || z.view === view))
  if (!zone) throw notFound(`zone ${name}`)
  return zone
}

function leasesFor(state, family, nodeId) {
  return state.leases[family].filter((l) => l.node_id === (nodeId || state.selfId))
}

function utilization(state, family, nodeId) {
  const leases = leasesFor(state, family, nodeId)
  const items = []
  for (const subnet of state.subnets[family]) {
    for (const p of subnet.pools) {
      const inside = leases.filter((l) => l.subnet_id === subnet.id && (family === 'v6' ? l.lease_type !== 'IA_PD' : inPool4(l.ip_address, p.pool)))
      const assigned = inside.filter((l) => l.state === 'default').length
      const declined = inside.filter((l) => l.state === 'declined').length
      const total = poolSize(p.pool, family)
      items.push({ subnet_id: subnet.id, subnet: subnet.subnet, pool: p.pool, kind: 'pool', total, assigned, declined, percent: Math.round((assigned / total) * 1000) / 10, node_id: nodeId || state.selfId })
    }
    for (const pd of subnet.pd_pools || []) {
      const delegated = leases.filter((l) => l.subnet_id === subnet.id && l.lease_type === 'IA_PD' && l.state === 'default').length
      const total = 2 ** (pd.delegated_len - pd.prefix_len)
      items.push({ subnet_id: subnet.id, subnet: subnet.subnet, pool: `${pd.prefix}/${pd.prefix_len}`, kind: 'pd-pool', total, assigned: delegated, declined: 0, percent: Math.round((delegated / total) * 1000) / 10, node_id: nodeId || state.selfId })
    }
  }
  return items
}

function subnetUtilization(state, family) {
  const out = {}
  for (const row of utilization(state, family)) {
    const cur = out[row.subnet_id] || { total: 0, assigned: 0, declined: 0, percent: 0 }
    cur.total += row.total
    cur.assigned += row.assigned
    cur.declined += row.declined
    cur.percent = Math.round((cur.assigned / cur.total) * 1000) / 10
    out[row.subnet_id] = cur
  }
  return out
}

// Expanded IPv6 as 32 hex nibbles; canonical compression is not needed for matching.
function v6Nibbles(ip) {
  const [head, tail = ''] = ip.toLowerCase().split('::')
  const h = head ? head.split(':') : []
  const t = ip.includes('::') && tail ? tail.split(':') : []
  const groups = [...h, ...Array(ip.includes('::') ? 8 - h.length - t.length : 0).fill('0'), ...t]
  return groups.map((g) => g.padStart(4, '0')).join('')
}

function canonicalV6(nibbles) {
  const groups = nibbles.match(/.{4}/g).map((g) => g.replace(/^0+(?=.)/, ''))
  let best = [-1, 0]
  for (let i = 0; i < 8; i += 1) {
    let j = i
    while (j < 8 && groups[j] === '0') j += 1
    if (j - i > best[1] && j - i > 1) best = [i, j - i]
  }
  if (best[0] < 0) return groups.join(':')
  return `${groups.slice(0, best[0]).join(':')}::${groups.slice(best[0] + best[1]).join(':')}`
}

// Address of an in-addr.arpa or ip6.arpa owner name, or null.
function reverseToIp(name) {
  const labels = absName(name).split('.').slice(0, -1)
  if (labels.slice(-2).join('.') === 'in-addr.arpa' && labels.length === 6) return labels.slice(0, 4).reverse().join('.')
  if (labels.slice(-2).join('.') === 'ip6.arpa' && labels.length === 34) return canonicalV6(labels.slice(0, 32).reverse().join(''))
  return null
}

const ipSortKey = (ip = '') => (ip.includes(':') ? [6, v6Nibbles(ip)] : [4, String(ipToInt(ip)).padStart(12, '0')])

// Kinds that take an admin exception: consistency checks and the exceptable health checks.
const EXCEPTION_KINDS = new Set([...INCONSISTENCY_KINDS, ...EXCEPTABLE_KINDS, 'security_finding'])

// The join of the hosts service: hosts merge on a shared MAC, then IP, then name,
// over v4 and (when the module is on) v6 leases, reservations, A/AAAA and PTR records.
function buildHosts(state) {
  const hosts = new Map()
  const byMac = new Map()
  const byIp = new Map()
  const byName = new Map()
  const attach = (mac, ips, name) => {
    ips = ips.filter(Boolean)
    name = name ? absName(name.includes('.') ? name : `${name}.example.lan`) : null
    let host = (mac && hosts.get(byMac.get(mac))) || ips.map((ip) => hosts.get(byIp.get(ip))).find(Boolean) || (name && hosts.get(byName.get(name)))
    if (!host) {
      const key = mac ? `mac:${mac}` : ips.length ? `ip:${ips[0]}` : `name:${name}`
      host = { key, mac: null, ips: [], hostname: null, lease: null, reservation: null, records: [], alerts: [] }
      hosts.set(key, host)
    }
    if (mac && !host.mac) host.mac = mac
    for (const ip of ips) if (!host.ips.includes(ip)) host.ips.push(ip)
    if (name && !host.hostname) host.hostname = name
    if (host.mac) byMac.set(host.mac, host.key)
    for (const ip of host.ips) byIp.set(ip, host.key)
    if (host.hostname) byName.set(host.hostname, host.key)
    return host
  }
  const families = state.modules.cluster.dhcpv6 ? ['v4', 'v6'] : ['v4']
  for (const family of families) {
    for (const lease of leasesFor(state, family)) {
      if (lease.lease_type === 'IA_PD') continue
      const host = attach(lease.hw_address, [lease.ip_address], lease.hostname)
      if (!host.lease) host.lease = lease
    }
    for (const r of state.reservations[family]) {
      const host = attach(r.id_type === 'hw-address' ? r.identifier : null, r.ip_address ? [r.ip_address] : r.ip_addresses, r.hostname)
      if (!host.reservation) host.reservation = r
    }
  }
  for (const zone of state.zones) {
    for (const rrset of state.records[zone.name] || []) {
      if (rrset.rtype === 'A' || rrset.rtype === 'AAAA') {
        for (const ip of rrset.rdata) {
          const host = attach(null, [ip], rrset.name)
          if (!host.records.includes(rrset)) host.records.push(rrset)
        }
      } else if (rrset.rtype === 'PTR') {
        const ip = reverseToIp(rrset.name)
        if (!ip) continue
        const host = attach(null, [ip], rrset.rdata[0])
        if (!host.records.includes(rrset)) host.records.push(rrset)
      }
    }
  }
  for (const host of hosts.values()) {
    host.alerts = state.alerts.filter((a) => a.state !== 'resolved' && host.ips.some((ip) => a.subject === `ip:${ip}`))
  }
  return [...hosts.values()].sort((a, b) => {
    const [fa, ka] = ipSortKey(a.ips[0])
    const [fb, kb] = ipSortKey(b.ips[0])
    return fa - fb || (ka < kb ? -1 : ka > kb ? 1 : 0)
  })
}

// One HAState per relationship a server belongs to: a hub's other relationships follow it.
export function flatHa(states) {
  return states.flatMap((h) => [h, ...(h.other_relationships || []).filter((o) => o.enabled !== false)])
}

// What the collectors last saw of each node's leases: assigned count and newest transaction.
function leaseMarks(state, family, nodeId) {
  const held = state.leases[family].filter((l) => l.node_id === nodeId)
  if (!held.length) return { leases: null, last_lease_at: null }
  const assigned = held.filter((l) => l.state === 'default').length
  return { leases: assigned, last_lease_at: held.map((l) => String(l.cltt)).sort().at(-1) }
}

// Every HA relationship across the nodes (connectors.kea.ha.relationships and
// DhcpService.relationships): each configured server with its role, node, state and leases; a
// backup with the servers it receives lease updates from and the primary it is compared with.
export function haRelationships(state, family) {
  const states = flatHa(state.ha[family].filter((h) => h.enabled !== false))
  if (!states.length) return []
  const hubs = new Set(state.ha[family].filter((h) => h.other_relationships?.length).map((h) => h.node_id))
  const groups = new Map()
  for (const h of states) {
    const key = (h.peers?.length ? h.peers.map((p) => p.name) : [h.server_name]).slice().sort().join(',')
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(h)
  }
  return [...groups.values()].map((members) => {
    const peers = members.find((h) => h.peers?.length)?.peers || members.map((h) => ({ name: h.server_name, role: h.role }))
    const servers = peers.map((p) => {
      const own = members.find((h) => h.server_name === p.name)
      const seenBy = members.find((h) => h.partner?.server_name === p.name)
      const partner = own?.partner?.server_name || (own && own.role !== 'backup' ? peers.find((o) => o.name !== p.name && o.role !== 'backup')?.name : null) || null
      return {
        name: p.name,
        role: p.role,
        url: p.url || null,
        auto_failover: p.auto_failover ?? null,
        node_id: own?.node_id || null,
        node_name: own ? nodeName(state, own.node_id) : null,
        state: own ? own.state : seenBy?.partner?.state || null,
        scopes: own?.scopes || [],
        unsent_update_count: own?.unsent_update_count ?? null,
        partner,
        in_touch: seenBy?.partner ? seenBy.partner.in_touch : null,
        collected_at: own?.collected_at || null,
        managed: Boolean(own),
        ...(own ? leaseMarks(state, family, own.node_id) : { leases: null, last_lease_at: null }),
      }
    })
    const active = servers.filter((s) => s.role !== 'backup').map((s) => s.name)
    const order = { primary: 0, secondary: 1, standby: 1 }
    const ref = servers.filter((s) => s.role in order && s.leases !== null && !hubs.has(s.node_id)).sort((a, b) => order[a.role] - order[b.role])[0]
    for (const s of servers) {
      if (s.role !== 'backup') continue
      s.receives_from = active
      s.lease_reference = ref ? { server: ref.name, leases: ref.leases } : null
    }
    return { family, mode: members[0].mode, servers, active, backups: servers.filter((s) => s.role === 'backup').map((s) => s.name) }
  })
}

const HA_MODE_ROLES = {
  'hot-standby': { primary: [1, 1], standby: [1, 1], backup: [0, Infinity] },
  'load-balancing': { primary: [1, 1], secondary: [1, 1], backup: [0, Infinity] },
  'passive-backup': { primary: [1, 1], backup: [1, Infinity] },
}

// HA state as status-get reads it now: the partner age follows the mock's heartbeats.
function liveHa(h, now = Date.now()) {
  if (!h.partner || h.partner.in_touch === false) return h
  return { ...h, collected_at: new Date(now).toISOString(), partner: { ...h.partner, age: heartbeatAge(`${h.node_id}/${h.family}`, now) } }
}

function summary(state) {
  const pools = []
  for (const family of ['v4', 'v6']) {
    for (const row of utilization(state, family)) {
      pools.push({ node_id: state.selfId, engine: family === 'v4' ? 'kea4' : 'kea6', subnet_id: row.subnet_id, subnet: row.subnet, pool: row.pool, kind: row.kind, total: row.total, assigned: row.assigned, declined: row.declined, percent: row.percent })
    }
  }
  const open = visibleAlerts(state).filter((a) => a.state === 'open')
  return {
    nodes: state.nodes,
    ha: [...state.ha.v4, ...state.ha.v6].map((h) => liveHa(h)),
    pools,
    zones: state.zones.filter((z) => z.kind !== 'forward').map((z) => ({ zone: z.name, view: z.view, kind: z.kind, ...zoneSerials(state, z) })),
    d2: Object.values(state.d2),
    alerts: {
      open: open.length,
      critical: open.filter((a) => a.severity === 'critical').length,
      warning: open.filter((a) => a.severity === 'warning').length,
      info: open.filter((a) => a.severity === 'info').length,
      unavailable: state.alertsUnavailable || [],
    },
    engines: capabilities(state).engines,
    errors: {},
    // Additive: the pool alert thresholds of [settings], so the tile needs no admin read.
    thresholds: {
      pool_warning_percent: setting(state, 'checks.pool_warning_percent'),
      pool_critical_percent: setting(state, 'checks.pool_critical_percent'),
      serial_divergence_seconds: setting(state, 'checks.serial_divergence_seconds'),
      d2_error_percent: setting(state, 'checks.d2_error_percent'),
    },
  }
}

function capabilities(state) {
  const self = state.nodes.find((n) => n.is_self)
  return {
    node: self,
    modules: { ...state.modules.cluster },
    engines: {
      bind: state.dnsCapabilities,
      kea4: state.dhcpCapabilities.v4,
      kea6: state.modules.cluster.dhcpv6 ? state.dhcpCapabilities.v6 : null,
      d2: { engine: 'd2', version: '3.2.1', running: true, control_socket: '/run/kea/kea-ddns-ctrl-socket' },
    },
  }
}

function bindStats(state, nodeId) {
  const zones = {}
  for (const z of state.zones) zones[`${z.view}/${z.name}`] = { serial: zoneSerials(state, z).serials[nodeId] ?? 0, QryAuthAns: 1200, QryNxrrset: 31, XfrSuccess: 4 }
  return {
    node_id: nodeId,
    collected_at: new Date().toISOString(),
    version: state.dnsCapabilities.version,
    boot_time: iso(Date.now() - 86400000 * 6),
    config_time: iso(Date.now() - 3600000),
    // Traffic grows over time (mock/live.mjs) so the dashboard rates move.
    opcodes: { ...liveCounters(nodeId, { QUERY: [184233, nodeId === state.selfId ? 420 : 310] }), NOTIFY: 52, UPDATE: 2840 },
    rcodes: liveCounters(nodeId, { NOERROR: [170020, nodeId === state.selfId ? 380 : 282], NXDOMAIN: [13110, nodeId === state.selfId ? 36 : 25], SERVFAIL: [12, 0.6], REFUSED: [91, 2.4] }),
    qtypes: { A: 98120, AAAA: 61002, PTR: 15020, MX: 410, TXT: 2211, SRV: 3880, SOA: 2540, NS: 50 },
    nsstats: { Requestv4: 150020, Requestv6: 34213, Response: 184233, QryRecursion: 40210, UpdateDone: 2840, UpdateFail: 2 },
    zonestats: { NotifyOutv4: 52, XfrReqDone: 9, XfrSuccess: 9 },
    resstats: { Queryv4: 40210, Mismatch: 0, Retry: 41, ValOk: 3022, ValNegOk: 120, ValFail: 0 },
    sockstats: { UDP4Open: 12, TCP4Open: 4, UDP6Open: 12, TCP6Open: 4 },
    memory: { TotalUse: 61234567, InUse: 23456789 },
    zones,
    raw: {},
  }
}

function grammar() {
  const s = (name, contexts, args, extra = {}) => ({ name, contexts, args, multiple: false, doc: `https://bind9.readthedocs.io/en/v9.20/reference.html#namedconf-statement-${name}`, ...extra })
  return {
    version: '9.20',
    statements: [
      s('options', ['toplevel'], 'block'),
      s('acl', ['toplevel'], 'string { address_match_element; ... }', { multiple: true }),
      s('key', ['toplevel', 'view'], 'string { algorithm string; secret string; }', { multiple: true }),
      s('zone', ['toplevel', 'view'], 'string [ class ] { ... }', { multiple: true }),
      s('view', ['toplevel'], 'string [ class ] { ... }', { multiple: true }),
      s('controls', ['toplevel'], 'block'),
      s('statistics-channels', ['toplevel'], 'block'),
      s('logging', ['toplevel'], 'block'),
      s('include', ['toplevel', 'options', 'view', 'zone'], 'quoted_string', { multiple: true }),
      s('directory', ['options'], 'quoted_string'),
      s('recursion', ['options', 'view'], 'boolean'),
      s('allow-recursion', ['options', 'view'], 'address_match_list'),
      s('allow-query', ['options', 'view', 'zone'], 'address_match_list'),
      s('allow-transfer', ['options', 'view', 'zone'], '[ port integer ] [ transport string ] address_match_list'),
      s('allow-update', ['zone'], 'address_match_list'),
      s('update-policy', ['zone'], 'local | { rule; ... }'),
      s('forwarders', ['options', 'view', 'zone'], '[ port integer ] { ( ipv4_address | ipv6_address ) [ port integer ]; ... }'),
      s('forward', ['options', 'view', 'zone'], '( first | only )'),
      s('dnssec-validation', ['options', 'view'], '( yes | no | auto )'),
      s('dnssec-policy', ['options', 'view', 'zone'], 'string'),
      s('notify', ['options', 'view', 'zone'], '( explicit | master-only | primary-only | boolean )'),
      s('also-notify', ['options', 'view', 'zone'], '{ remote-servers; ... }'),
      s('primaries', ['toplevel', 'zone'], 'string { remote-servers; ... }', { multiple: true }),
      s('response-policy', ['options', 'view'], '{ zone string [ policy ... ]; ... }'),
      s('catalog-zones', ['options', 'view'], '{ zone string [ ... ]; ... }'),
      s('listen-on', ['options'], '[ port integer ] [ tls string ] { address_match_list }', { multiple: true }),
      s('listen-on-v6', ['options'], '[ port integer ] [ tls string ] { address_match_list }', { multiple: true }),
      s('type', ['zone'], '( primary | secondary | stub | static-stub | forward | mirror | hint | redirect )'),
      s('file', ['zone'], 'quoted_string'),
      s('keys', ['dnssec-policy'], '{ ( csk | ksk | zsk ) [ key-directory | key-store string ] lifetime duration algorithm string [ tag-range integer integer ] [ integer ]; ... }'),
      s('signatures-validity', ['dnssec-policy'], 'duration'),
      s('signatures-refresh', ['dnssec-policy'], 'duration'),
      s('nsec3param', ['dnssec-policy'], '[ iterations integer ] [ optout boolean ] [ salt-length integer ]'),
      s('max-zone-ttl', ['dnssec-policy'], 'duration'),
      s('dnskey-ttl', ['dnssec-policy'], 'duration'),
      s('inline-signing', ['dnssec-policy'], 'boolean'),
    ],
  }
}

function bindTree(state) {
  const st = (name, value, line, children) => ({ name, value, line, ...(children ? { children } : {}) })
  return {
    files: [
      {
        path: '/etc/bind/named.conf',
        managed: false,
        statements: [
          st('include', '"/etc/bind/named.conf.options"', 1),
          st('include', '"/etc/bind/named.conf.local"', 2),
          st('include', '"/etc/bind/pelagos/pelagos.conf"', 3),
        ],
      },
      {
        path: '/etc/bind/named.conf.options',
        managed: false,
        statements: [
          st('options', null, 1, [
            st('directory', '"/var/cache/bind"', 2),
            st('recursion', state.resolver.recursion ? 'yes' : 'no', 3),
            st('allow-recursion', `{ ${state.resolver.allow_recursion.join('; ')}; }`, 4),
            st('forwarders', `{ ${state.resolver.forwarders.join('; ')}; }`, 5),
            st('forward', state.resolver.forward, 6),
            st('dnssec-validation', state.resolver.dnssec_validation, 7),
            st('include', '"/etc/bind/pelagos/options.conf"', 8),
          ]),
        ],
      },
      {
        path: '/etc/bind/named.conf.local',
        managed: false,
        statements: state.zones
          .filter((z) => z.source === 'user_conf')
          .map((z, i) => st('zone', `"${z.name.replace(/\.$/, '')}"`, i * 6 + 1, [st('type', z.kind, i * 6 + 2), ...(z.file ? [st('file', `"${z.file}"`, i * 6 + 3)] : [])])),
      },
      {
        path: '/etc/bind/pelagos/keys.conf',
        managed: true,
        statements: state.keys
          .filter((k) => k.source === 'pelagos')
          .map((k, i) => st('key', `"${k.name}"`, i * 4 + 1, [st('algorithm', k.algorithm, i * 4 + 2), st('secret', '"********"', i * 4 + 3)])),
      },
      {
        path: '/etc/bind/pelagos/zones.conf',
        managed: true,
        statements: state.zones
          .filter((z) => z.source === 'pelagos')
          .map((z, i) => st('zone', `"${z.name.replace(/\.$/, '')}"`, i * 6 + 1, [st('type', z.kind, i * 6 + 2), st('file', `"${z.file}"`, i * 6 + 3)])),
      },
    ],
  }
}

// BindConfigTree (architecture section 4): statements as {name, value, path, line, managed}.
function bindConfig(state, nodeId) {
  const options = '/etc/bind/named.conf.options'
  const managedOptions = '/etc/bind/pelagos/options.conf'
  const opt = (name, value, path = managedOptions, line = 1) => ({ name, value, path, line, managed: path.startsWith('/etc/bind/pelagos/') })
  return {
    node_id: nodeId || state.selfId,
    user_conf: '/etc/bind/named.conf',
    includes: ['/etc/bind/named.conf', options, '/etc/bind/named.conf.local', '/etc/bind/pelagos/pelagos.conf', '/etc/bind/pelagos/keys.conf', '/etc/bind/pelagos/acls.conf', '/etc/bind/pelagos/zones.conf', managedOptions],
    options: [
      opt('directory', '"/var/cache/bind"', options, 2),
      opt('recursion', state.resolver.recursion ? 'yes' : 'no'),
      opt('allow-recursion', `{ ${state.resolver.allow_recursion.join('; ')}; }`, managedOptions, 2),
      opt('forwarders', `{ ${state.resolver.forwarders.join('; ')}; }`, managedOptions, 3),
      opt('forward', state.resolver.forward, managedOptions, 4),
      opt('dnssec-validation', state.resolver.dnssec_validation, managedOptions, 5),
    ],
    keys: state.keys.map((k, i) => ({ name: k.name, value: `algorithm ${k.algorithm}; secret "***"`, path: k.config_path, line: 1 + i * 4, managed: k.source === 'pelagos' })),
    acls: state.acls.map((a, i) => ({ name: a.name, value: `{ ${a.elements.join('; ')}; }`, path: a.config_path, line: 1 + i * 3, managed: a.source === 'pelagos' })),
    controls: [{ name: 'inet', value: '127.0.0.1 port 953 allow { 127.0.0.1; } keys { "rndc-key"; }', path: options, line: 20, managed: false }],
    statistics_channels: [{ name: 'inet', value: '127.0.0.1 port 8053 allow { 127.0.0.1; }', path: options, line: 24, managed: false }],
    logging: 'logging {\n\tchannel default_log { file "/var/log/named/default.log" versions 3 size 20m; severity info; };\n};',
    views: {},
    zones: state.zones,
    pelagos: {
      include_dir: '/etc/bind/pelagos',
      managed_files: { 'pelagos.conf': true, 'keys.conf': true, 'acls.conf': true, 'zones.conf': true, 'options.conf': true },
      view_files: [],
      include_line_present: true,
      options_include_present: true,
      view_includes_present: {},
      missing_includes: [],
      parse_errors: [],
      other_statements: [],
      has_views: false,
      checkconf: { ok: true, output: '' },
    },
    collected_at: iso(Date.now()),
  }
}

function keaSchema(family) {
  const root = family === 'v4' ? 'Dhcp4' : 'Dhcp6'
  const k = (name, type, description, extra = {}) => ({ name, type, description, ...extra })
  if (family === 'd2') {
    return {
      root: 'DhcpDdns',
      version: '3.2.1',
      keys: [
        k('ip-address', 'string', 'Address D2 listens on for name change requests'),
        k('port', 'integer', 'Port D2 listens on', { minimum: 1, maximum: 65535 }),
        k('control-sockets', 'array', 'Control channels (3.x)', { since: '2.7.2' }),
        k('tsig-keys', 'array', 'TSIG keys signing the DNS updates'),
        k('forward-ddns', 'object', 'Forward zones and their DNS servers'),
        k('reverse-ddns', 'object', 'Reverse zones and their DNS servers'),
        k('loggers', 'array', 'Logging configuration'),
      ],
    }
  }
  return {
    root,
    version: '3.2.1',
    keys: [
      k('interfaces-config', 'object', 'Interfaces to listen on'),
      k('control-sockets', 'array', 'Control channels (3.x)', { since: '2.7.2' }),
      k('lease-database', 'object', 'Lease storage backend'),
      k('hosts-database', 'object', 'Host reservation backend'),
      k('valid-lifetime', 'integer', 'Default lease lifetime in seconds', { minimum: 0 }),
      k('renew-timer', 'integer', 'T1 in seconds', { minimum: 0 }),
      k('rebind-timer', 'integer', 'T2 in seconds', { minimum: 0 }),
      ...(family === 'v6' ? [k('preferred-lifetime', 'integer', 'Preferred lifetime in seconds', { minimum: 0 })] : []),
      k('option-data', 'array', 'Global options'),
      k('option-def', 'array', 'Custom option definitions'),
      k('client-classes', 'array', 'Client classification'),
      k(family === 'v4' ? 'subnet4' : 'subnet6', 'array', 'Subnets'),
      k('shared-networks', 'array', 'Shared networks'),
      k('reservations', 'array', 'Global reservations'),
      k('hooks-libraries', 'array', 'Loaded hook libraries'),
      k('dhcp-ddns', 'object', 'Connection to kea-dhcp-ddns'),
      k('ddns-send-updates', 'boolean', 'Send DNS updates'),
      k('ddns-qualifying-suffix', 'string', 'Suffix appended to partial names'),
      k('multi-threading', 'object', 'Packet processing threads'),
      k('loggers', 'array', 'Logging configuration'),
      k('user-context', 'object', 'Free-form data kept by Kea'),
    ],
  }
}

function keaConfig(state, family) {
  const subnetKey = family === 'v4' ? 'subnet4' : 'subnet6'
  const toKea = (s) => ({
    id: s.id,
    subnet: s.subnet,
    pools: s.pools.map((p) => ({ pool: p.pool, ...(p.client_classes.length ? { 'client-classes': p.client_classes } : {}) })),
    ...(s.pd_pools.length ? { 'pd-pools': s.pd_pools.map((p) => ({ prefix: p.prefix, 'prefix-len': p.prefix_len, 'delegated-len': p.delegated_len })) } : {}),
    'option-data': s.options.map((o) => ({ name: o.name, code: o.code, data: o.data })),
    'valid-lifetime': s.valid_lifetime,
    'user-context': s.user_context,
  })
  return {
    [family === 'v4' ? 'Dhcp4' : 'Dhcp6']: {
      'interfaces-config': { interfaces: ['eth1'] },
      'control-sockets': [{ 'socket-type': 'unix', 'socket-name': state.dhcpCapabilities[family].control_socket }],
      'lease-database': { type: 'memfile', persist: true, 'lfc-interval': 3600 },
      'valid-lifetime': 3600,
      'option-data': state.globalOptions[family].map((o) => ({ name: o.name, code: o.code, data: o.data })),
      'client-classes': state.classes[family].map((c) => ({ name: c.name, test: c.test })),
      [subnetKey]: state.subnets[family].filter((s) => !s.shared_network).map(toKea),
      'shared-networks': state.sharedNetworks[family].map((n) => ({ name: n.name, [subnetKey]: state.subnets[family].filter((s) => s.shared_network === n.name).map(toKea) })),
      'hooks-libraries': state.hooks[family].map((h) => ({ library: h.library, parameters: h.parameters })),
      'dhcp-ddns': state.ddns[family].dhcp_ddns,
      ...state.ddns[family].ddns_params,
    },
  }
}

// GET /dhcp/{family}/config returns the bare object under the root key, as
// KeaBackend.config_get() does; the editor accepts both shapes.
const bareKea = (wrapped) => Object.values(wrapped)[0]

function d2Config() {
  return {
    DhcpDdns: {
      'ip-address': '127.0.0.1',
      port: 53001,
      'control-sockets': [{ 'socket-type': 'unix', 'socket-name': '/run/kea/kea-ddns-ctrl-socket' }],
      'tsig-keys': [{ name: 'ddi-admin', algorithm: 'HMAC-SHA256', 'secret-file': '/etc/kea/ddi-admin.secret' }],
      'forward-ddns': { 'ddns-domains': [{ name: 'example.lan.', 'key-name': 'ddi-admin', 'dns-servers': [{ 'ip-address': '192.0.2.53', port: 53 }] }] },
      'reverse-ddns': { 'ddns-domains': [{ name: '2.0.192.in-addr.arpa.', 'key-name': 'ddi-admin', 'dns-servers': [{ 'ip-address': '192.0.2.53', port: 53 }] }] },
    },
  }
}

function seriesPools(state, query) {
  const to = parseTime(query.get('to')) || Date.now()
  const from = parseTime(query.get('from')) || to - 86400000
  const step = Math.max(60, parseInt(query.get('step') || '3600', 10)) * 1000
  const engine = query.get('engine') || 'kea4'
  const family = engine === 'kea6' ? 'v6' : 'v4'
  const subnetId = query.get('subnet_id')
  const nodeId = query.get('node_id') || state.selfId
  const rows = utilization(state, family, nodeId).filter((r) => !subnetId || String(r.subnet_id) === subnetId)
  return {
    series: rows
      .filter((r) => !query.get('pool') || r.pool === query.get('pool'))
      .map((r, idx) => {
        // Samples recorded by mock events replace the synthetic curve from their first instant.
        const recorded = (state.poolHistory?.[poolHistoryKey(engine, r.subnet_id, r.pool, nodeId)] || []).filter(([ts]) => ts * 1000 >= from && ts * 1000 <= to)
        const until = recorded.length ? recorded[0][0] * 1000 : Infinity
        const points = []
        for (let t = from, i = 0; t <= to && t < until && i < 2000; t += step, i += 1) {
          // A daily swell and a 7 min churn; the newest point is the pool as it is now.
          const wave = Math.sin((t / 3600000 / 24) * Math.PI * 2 + idx) * 0.08 + Math.sin((t / 420000) * Math.PI * 2 + idx) * 0.03
          const assigned = to - t < step ? r.assigned : Math.max(0, Math.min(r.total, Math.round(r.assigned * (0.93 + wave))))
          points.push([Math.floor(t / 1000), assigned, r.total])
        }
        points.push(...recorded)
        return { key: { engine, subnet_id: r.subnet_id, pool: r.pool, node_id: nodeId }, points }
      }),
  }
}

function parseTime(value) {
  if (!value) return null
  if (/^\d+$/.test(value)) return Number(value) * 1000
  const t = Date.parse(value)
  return Number.isNaN(t) ? null : t
}

function haTransitions(state, family) {
  const base = Date.now()
  return [
    { ts: iso(base - 3600000 * 30), node_id: state.nodeIds.ns2, server_name: 'ns2', from_state: 'waiting', to_state: 'syncing', partner_state: 'hot-standby' },
    { ts: iso(base - 3600000 * 30 + 40000), node_id: state.nodeIds.ns2, server_name: 'ns2', from_state: 'syncing', to_state: 'ready', partner_state: 'hot-standby' },
    { ts: iso(base - 3600000 * 30 + 45000), node_id: state.nodeIds.ns2, server_name: 'ns2', from_state: 'ready', to_state: 'hot-standby', partner_state: 'hot-standby' },
    { ts: iso(base - 3600000 * 2), node_id: state.nodeIds.ns1, server_name: 'ns1', from_state: 'hot-standby', to_state: 'partner-down', partner_state: 'unavailable' },
    { ts: iso(base - 3600000 * 2 + 300000), node_id: state.nodeIds.ns1, server_name: 'ns1', from_state: 'partner-down', to_state: 'hot-standby', partner_state: 'hot-standby' },
  ].map((t) => ({ ...t, family }))
}

// ------------------------------------------------------------------ plan builders

function rrsetPlan(state, user, zoneName, body) {
  const zone = findZone(state, zoneName, body.view)
  if (!Array.isArray(body.changes) || body.changes.length === 0) throw invalid('changes', 'at least one change is required')
  const records = state.records[zone.name]
  const normalized = body.changes.map((c, i) => {
    if (!['add', 'delete', 'replace'].includes(c.op)) throw invalid(`changes[${i}].op`, 'must be add, delete or replace')
    const [, owner = '', rtype = ''] = String(c.target || '').split('/')
    const name = owner === '@' || owner === '' ? zone.name : owner.endsWith('.') ? owner.toLowerCase() : `${owner.toLowerCase()}.${zone.name}`
    const before = records.find((r) => r.name === name && r.rtype === rtype.toUpperCase()) || null
    const after = c.op === 'delete' ? null : { name, rtype: rtype.toUpperCase(), ttl: Number(c.after?.ttl ?? 3600), rdata: [].concat(c.after?.rdata || []) }
    if (after && after.ttl < 0) throw invalid(`changes[${i}].after.ttl`, 'must be >= 0')
    return { op: c.op, target: `${zone.name}/${name}/${rtype.toUpperCase()}`, before, after, node_ids: c.node_ids || [] }
  })
  // The PTR of the A/AAAA changes, in the same plan (services/ptr_service.py).
  const ptr = body.ptr ? state.ptr.ptrChanges(normalized, body.ptr, body.ptr.reverse_view || body.view) : { changes: [], replaced: [] }
  const all = [...normalized, ...ptr.changes]
  const zonesOf = [...new Set(all.map((c) => c.target.split('/')[0]))]
  const oldText = all.map((c) => rrsetText(c.before)).filter(Boolean).join('\n')
  const newText = all.map((c) => rrsetText(c.after)).filter(Boolean).join('\n')
  const serial = state.soaSerial(records)
  const bad = normalized.some((c) => c.after?.rdata.some((r) => /invalid/i.test(r)))
  const snapshots = Object.fromEntries(zonesOf.map((z) => [z, JSON.parse(JSON.stringify(state.records[z]))]))
  const replacedText = ptr.replaced.map((r) => `the PTR of ${r.ip} pointed to ${r.targets.join(', ')} and is replaced`)
  return createPlan(state, user, {
    scope: 'dns.rrset',
    engine: 'bind',
    summary: `${normalized.length} change(s) in ${zone.name}${ptr.changes.length ? ` (PTR in ${zonesOf.slice(1).join(', ')})` : ''}${replacedText.map((t) => ` (${t})`).join('')}`,
    changes: all,
    diff: unifiedDiff(oldText, newText, zone.name),
    targets: [state.selfId],
    tool: 'dnspython',
    requires_confirmation: ptr.replaced.length > 0,
    preconditions: [
      { kind: 'soa_serial', node_id: state.selfId, subject: zone.name, value: String(serial) },
      ...all.map((c) => ({ kind: c.before ? 'rrset_exists' : 'rrset_absent', node_id: state.selfId, subject: c.target, value: c.before ? c.before.rdata.join(' ') : '' })),
    ],
    validations: [
      { ok: !bad, tool: 'dnspython', output: bad ? 'rdata does not parse' : '', node_id: state.selfId },
      ...(replacedText.length ? [{ ok: true, tool: 'ptr', output: replacedText.join('; '), node_id: state.selfId }] : []),
    ],
    apply() {
      applyRecordChanges(state, all, zonesOf)
      return 'NOERROR'
    },
    // A rollback is a new change: its serial goes above the applied one, never back.
    rollback() {
      restoreZones(state, snapshots)
    },
  })
}

function applyRecordChanges(state, changes, zones) {
  for (const c of changes) {
    const table = state.records[c.target.split('/')[0]]
    const idx = table.findIndex((r) => r.name === c.before?.name && r.rtype === c.before?.rtype)
    if (c.before && idx >= 0) table.splice(idx, 1)
    if (c.after) table.push(c.after)
  }
  for (const z of zones) bumpSerial(state.records[z])
}

function restoreZones(state, snapshots) {
  for (const [z, snapshot] of Object.entries(snapshots)) {
    const table = state.records[z]
    const current = state.soaSerial(table)
    table.splice(0, table.length, ...JSON.parse(JSON.stringify(snapshot)))
    setSerial(table, current + 1)
  }
}

// POST /dns/ptr/orphans/plan: PTR targets removed and missing addresses created, in one plan.
function orphansPlan(state, user, body) {
  const deletes = body.delete || []
  const creates = body.create || []
  if (!Array.isArray(deletes) || !Array.isArray(creates) || deletes.length + creates.length === 0) throw invalid('delete', 'required')
  const changes = []
  const byTarget = new Map()
  deletes.forEach((d, i) => {
    const zone = absName(d.zone || '')
    if (!zone.endsWith('.arpa.') || !absName(d.name || '').endsWith(zone)) throw invalid(`delete[${i}]`, 'name must be in the reverse zone')
    const key = `${zone}|${absName(d.name)}`
    byTarget.set(key, [...(byTarget.get(key) || []), absName(d.target || '')])
  })
  for (const [key, targets] of byTarget) {
    const [zone, name] = key.split('|')
    const current = state.ptr.rrset(zone, name, 'PTR')
    if (!current) continue
    const want = current.rdata.filter((t) => !targets.includes(t))
    const target = `${zone}/${name}/PTR`
    changes.push(want.length ? { op: 'replace', target, before: current, after: { ...current, rdata: want }, node_ids: [] } : { op: 'delete', target, before: current, after: null, node_ids: [] })
  }
  creates.forEach((c, i) => {
    const ip = state.ptr.canonical(c.ip)
    if (!ip) throw invalid(`create[${i}].ip`, 'a valid address')
    const name = absName(c.target || '')
    const zone = state.ptr.bestZone(name, c.view, false)
    if (!zone) throw invalid('create', `${name} is not in a zone served by the cluster`)
    const rtype = ip.includes(':') ? 'AAAA' : 'A'
    const current = state.ptr.rrset(zone.name, name, rtype)
    const target = `${zone.name}/${name}/${rtype}`
    if (!current) changes.push({ op: 'add', target, before: null, after: { name, rtype, ttl: 3600, rdata: [ip] }, node_ids: [] })
    else if (!current.rdata.includes(ip)) changes.push({ op: 'replace', target, before: current, after: { ...current, rdata: [...current.rdata, ip] }, node_ids: [] })
  })
  if (!changes.length) throw new Problem(409, 'conflict', 'the PTR records already match; nothing to change')
  const zonesOf = [...new Set(changes.map((c) => c.target.split('/')[0]))]
  const snapshots = Object.fromEntries(zonesOf.map((z) => [z, JSON.parse(JSON.stringify(state.records[z]))]))
  const deleted = [...byTarget.values()].reduce((n, t) => n + t.length, 0)
  return createPlan(state, user, {
    scope: 'dns.rrset',
    engine: 'bind',
    summary: `PTR cleanup: ${deleted} PTR targets removed, ${creates.length} addresses added`,
    summary_message: { key: 'plan.ptr.cleanup', params: { deleted, created: creates.length } },
    changes,
    diff: unifiedDiff(changes.map((c) => rrsetText(c.before)).filter(Boolean).join('\n'), changes.map((c) => rrsetText(c.after)).filter(Boolean).join('\n'), 'PTR cleanup'),
    targets: [state.selfId],
    tool: 'dnspython',
    requires_confirmation: deletes.length > 0,
    apply() {
      applyRecordChanges(state, changes, zonesOf)
      return 'NOERROR'
    },
    rollback() {
      restoreZones(state, snapshots)
    },
  })
}

function setSerial(records, serial) {
  const soa = records.find((r) => r.rtype === 'SOA')
  if (!soa) return
  const parts = soa.rdata[0].split(/\s+/)
  parts[2] = String(serial)
  soa.rdata[0] = parts.join(' ')
}

function bumpSerial(records) {
  const soa = records.find((r) => r.rtype === 'SOA')
  if (soa) setSerial(records, Number(soa.rdata[0].split(/\s+/)[2]) + 1)
}

// Generic plan over a list held in state: add/replace/delete by key.
function listPlan(state, user, { scope, engine, list, keyOf, change, label, tool, targetPrefix, confirm }) {
  if (!change || !['add', 'delete', 'replace'].includes(change.op)) throw invalid('change.op', 'must be add, delete or replace')
  const key = keyOf(change.op === 'delete' ? change.before || change.after || {} : change.after || {})
  if (key === undefined || key === null || key === '') throw invalid('change.after', 'identifying field missing')
  const idx = list.findIndex((item) => keyOf(item) === key)
  const before = idx >= 0 ? list[idx] : null
  if (change.op === 'add' && before) throw new Problem(409, 'conflict', `${label} ${key} already exists`)
  if (change.op !== 'add' && !before) throw notFound(`${label} ${key}`)
  const after = change.op === 'delete' ? null : { ...(before || {}), ...change.after }
  const snapshot = before ? JSON.parse(JSON.stringify(before)) : null
  const normalized = { op: change.op, target: `${targetPrefix}${key}`, before, after, node_ids: change.node_ids || [] }
  return createPlan(state, user, {
    scope,
    engine,
    summary: `${change.op} ${label} ${key}`,
    changes: [normalized],
    diff: unifiedDiff(jsonText(before), jsonText(after), `${label} ${key}`),
    targets: state.nodes.map((n) => n.peer.id),
    tool,
    requires_confirmation: confirm,
    preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: engine || scope, value: configHash(state, engine || scope) })),
    apply() {
      const at = list.findIndex((item) => keyOf(item) === key)
      if (change.op === 'delete') list.splice(at, 1)
      else if (at >= 0) list[at] = after
      else list.push(after)
    },
    rollback() {
      const at = list.findIndex((item) => keyOf(item) === key)
      if (at >= 0) list.splice(at, 1)
      if (snapshot) list.splice(idx >= 0 ? idx : list.length, 0, snapshot)
    },
  })
}

// Hand over to Pelagos: the statements leave the user file and show as managed afterwards.
function handoverPlan(state, user, body) {
  const items = body.changes.map((c) => {
    const item = state.handover.find((i) => i.target === c.target)
    if (!item) throw notFound(`statement ${String(c.target).replace(/^handover\//, '')} in a user file`)
    return item
  })
  const targets = body.node_ids || state.nodes.map((n) => n.peer.id)
  const diff = items.map((i) => `--- ${i.config_path}\n-${i.name} ${i.value}\n+++ /etc/bind/pelagos/${i.managed_file}\n+${i.name} ${i.value}\n`).join('')
  const flip = (list, name, to) => list.filter((x) => x.name === name).forEach((x) => Object.assign(x, to))
  return createPlan(state, user, {
    scope: 'dns.config',
    engine: 'bind',
    summary: `hand over ${items.length} statement(s) to Pelagos`,
    changes: items.map((i) => ({ op: 'replace', target: i.target, before: i.value, after: { file: i.managed_file, from: i.config_path, value: i.value, comment: true }, node_ids: [] })),
    diff,
    targets,
    validations: targets.flatMap((node_id) => [
      { ok: true, tool: 'named-checkconf', output: '', node_id },
      { ok: true, tool: 'effective-value', output: 'effective values unchanged', node_id },
    ]),
    preconditions: targets.map((node_id) => ({ kind: 'config_hash', node_id, subject: 'bind', value: configHash(state, 'bind') })),
    apply() {
      for (const i of items) {
        state.handover = state.handover.filter((x) => x.target !== i.target)
        if (i.kind === 'keys') flip(state.keys, i.name, { source: 'pelagos', config_path: '/etc/bind/pelagos/keys.conf' })
        if (i.kind === 'zones') flip(state.zones, i.name, { source: 'pelagos', config_path: '/etc/bind/pelagos/zones.conf' })
      }
    },
    rollback() {},
  })
}

function settingsPlan(state, user, { scope, engine, target, current, next, tool, confirm, apply, summary }) {
  const before = JSON.parse(JSON.stringify(current))
  return createPlan(state, user, {
    scope,
    engine,
    summary: summary || `update ${target}`,
    changes: [{ op: 'replace', target, before, after: next, node_ids: [] }],
    diff: unifiedDiff(jsonText(before), jsonText(next), target),
    targets: state.nodes.map((n) => n.peer.id),
    tool,
    requires_confirmation: confirm,
    preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: engine || scope, value: configHash(state, engine || scope) })),
    apply: () => apply(next),
    rollback: () => apply(before),
  })
}

// ------------------------------------------------------------------ handlers

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

// Plays the events of an apply or rollback at the pace of a cluster: each node's part takes
// `pace` ms, ending with its audit entry or its `step` done event.
async function replayPaced(queued, pace, emit) {
  let waited = false
  for (const [topic, event, data] of queued) {
    const ends = (topic === 'audit' && data?.request?.entry === 'node') || (topic === 'plans' && event === 'step' && data?.state !== 'running')
    if (ends && !waited) {
      await sleep(pace)
      waited = true
    }
    if (topic === 'plans' && event === 'step' && data?.state === 'running') waited = false
    emit(topic, event, data)
  }
}

function buildHandlers(state, emit) {
  // A record plan changed the zone on this node: its secondaries lag until the transfer.
  const markTransfer = (planId) => {
    const plan = state.plans.get(planId)?.plan
    if (plan?.scope !== 'dns.rrset' || !state.transferMs) return
    const zone = String(plan.changes?.[0]?.target || '').split('/')[0]
    if (!zone) return
    state.transferLag ||= {}
    state.transferLag[zone] = Date.now() + state.transferMs
    zoneEvents(state, emit, zone, state.transferMs)
  }
  const kea = (family) => (family === 'v4' ? 'kea4' : 'kea6')
  const keaTool = (family) => `kea-dhcp${family === 'v4' ? '4' : '6'} -t`
  const nodeOr = (q) => q.get('node_id') || state.selfId
  // GET and DELETE /plans/{id}: creator or admin.
  const ownPlan = (id, user) => {
    const held = state.plans.get(id)
    if (!held) throw notFound(`plan ${id}`)
    if (held.creator !== user.username && !isAdmin(user)) throw new Problem(403, 'forbidden', 'only the creator or an admin can see this plan')
    return held
  }
  // Failed logins per username; 5 within a minute answer 429 until they age out.
  const loginFailures = new Map()
  const recentFailures = (name) => (loginFailures.get(name) || []).filter((t) => Date.now() - t < LOGIN_WINDOW_MS)

  return {
    // Meta
    'GET /health': () => ({ status: 'ok', replication: 'ready', node_id: state.selfId, time: iso(Date.now()) }),
    'GET /version': () => ({ version: '0.1.0', api: 'v1', python: '3.12.11', build: 'mock' }),
    'GET /capabilities': () => capabilities(state),

    // Auth and account
    'POST /auth/login': ({ body, res }) => {
      const failures = recentFailures(body.username)
      if (failures.length >= LOGIN_MAX_FAILURES) {
        res.setHeader('Retry-After', String(Math.ceil((LOGIN_WINDOW_MS - (Date.now() - failures[0])) / 1000)))
        throw new Problem(429, 'rate_limited', 'Too many failed logins, try again later')
      }
      const fail = () => loginFailures.set(body.username, [...failures, Date.now()])
      const user = state.users.find((u) => u.username === body.username)
      if (!user || user.password !== body.password || !user.enabled) {
        fail()
        auditEntry(state, null, { action: 'auth.login', target: `user:${body.username}`, result: 'denied', message: 'invalid credentials' })
        throw new Problem(401, 'invalid_credentials', 'Invalid username or password')
      }
      if (user.has_totp) {
        if (!body.totp_code) throw new Problem(401, 'totp_required', 'A TOTP code is required')
        if (body.totp_code !== (user.totp || '123456')) {
          fail()
          throw new Problem(401, 'invalid_credentials', 'Invalid TOTP code')
        }
      }
      loginFailures.delete(body.username)
      const sid = randomBytes(32).toString('hex')
      const csrf = randomBytes(24).toString('hex')
      state.sessions.set(sid, { userId: user.id, csrf, created: Date.now() })
      user.last_login = iso(Date.now())
      res.setHeader('Set-Cookie', `pelagos_session=${sid}; HttpOnly; SameSite=Strict; Path=/`)
      auditEntry(state, user, { action: 'auth.login', target: `user:${user.username}` })
      return { user: publicUser(user, state), permissions: permissionsOf(state, user), csrf_token: csrf, totp_required: false }
    },
    'POST /auth/logout': ({ sid, res }) => {
      state.sessions.delete(sid)
      res.setHeader('Set-Cookie', 'pelagos_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
      return null
    },
    'GET /auth/session': ({ user, session }) => ({
      user: publicUser(user, state),
      permissions: user.permissions,
      csrf_token: session.csrf,
      node: state.nodes.find((n) => n.is_self),
    }),
    'POST /auth/password': ({ user, body }) => {
      const record = state.users.find((u) => u.id === user.id)
      if (record.password !== body.current_password) throw new Problem(401, 'invalid_credentials', 'Current password is wrong')
      checkPassword('new_password', body.new_password)
      record.password = body.new_password
      record.must_change_password = false
      return null
    },
    'POST /auth/totp/enroll': ({ user }) => {
      const secret = 'JBSWY3DPEHPK3PXP'
      state.pendingTotp = { userId: user.id, secret }
      return { secret, otpauth_url: `otpauth://totp/Pelagos:${user.username}?secret=${secret}&issuer=Pelagos&digits=6&period=30` }
    },
    'POST /auth/totp/confirm': ({ user, body }) => {
      if (state.pendingTotp?.userId !== user.id) throw new Problem(409, 'conflict', 'no TOTP enrollment in progress')
      if (!/^\d{6}$/.test(body.code || '')) throw invalid('code', 'must be 6 digits')
      const record = state.users.find((u) => u.id === user.id)
      record.has_totp = true
      record.totp = body.code
      state.pendingTotp = null
      return null
    },
    'DELETE /auth/totp': ({ user, body }) => {
      const record = state.users.find((u) => u.id === user.id)
      if (record.password !== body.password) throw new Problem(401, 'invalid_credentials', 'Password is wrong')
      record.has_totp = false
      return null
    },
    'GET /account/preferences': ({ user }) => ({
      theme_family: 'instrument',
      theme_mode: 'system',
      language: 'en',
      animations: 'full',
      ambient: 'on',
      dashboard_layout: null,
      ...(state.preferences.get(user.id) || {}),
    }),
    'PUT /account/preferences': ({ user, body }) => {
      const allowed = ['theme_family', 'theme_mode', 'language', 'animations', 'ambient', 'dashboard_layout']
      const merged = { ...(state.preferences.get(user.id) || {}) }
      for (const key of allowed) if (key in body) merged[key] = body[key]
      state.preferences.set(user.id, merged)
      return { theme_family: 'instrument', theme_mode: 'system', language: 'en', animations: 'full', ambient: 'on', dashboard_layout: null, ...merged }
    },

    // Nodes
    'GET /nodes': () => ({ items: state.nodes }),
    'GET /nodes/self': () => state.nodes.find((n) => n.is_self),
    'GET /nodes/{id}': ({ params }) => state.nodes.find((n) => n.peer.id === params.id || n.peer.name === params.id) || (() => { throw notFound(`node ${params.id}`) })(),
    'POST /nodes/enroll-token': ({ body }) => {
      const ttl = Number(body.ttl_seconds || 900)
      const token = randomBytes(16).toString('hex')
      const expires = iso(Date.now() + ttl * 1000)
      state.enrollTokens.push({ token, expires })
      return {
        token,
        url: 'https://ns1.example.lan:8444',
        ca_fingerprint: 'sha256:4f2a9c'.padEnd(71, '0'),
        expires_at: expires,
        command: `sudo pelagos enroll --url https://ns1.example.lan:8444 --token ${token} --ca-fingerprint sha256:4f2a9c... --name <name> --web-url https://<name>.example.lan:8443 --replication-url https://<name>.example.lan:8444`,
      }
    },
    'DELETE /nodes/{id}': ({ params, user }) => {
      const idx = state.nodes.findIndex((n) => n.peer.id === params.id)
      if (idx < 0) throw notFound(`node ${params.id}`)
      if (state.nodes[idx].is_self) throw new Problem(409, 'conflict', 'cannot remove the local node')
      const [removed] = state.nodes.splice(idx, 1)
      auditEntry(state, user, { action: 'node.remove', target: `node:${removed.peer.name}` })
      return null
    },
    'POST /nodes/{id}/sync': ({ params }) => {
      if (!state.nodes.some((n) => n.peer.id === params.id)) throw notFound(`node ${params.id}`)
      return { config_adopted: false, audit_added: 3 }
    },
    'GET /nodes/replication': () => ({
      state: 'ready',
      peers: state.nodes
        .filter((n) => !n.is_self)
        .map((n) => ({ node_id: n.peer.id, reachable: n.status === 'online', config_version: n.config_version, audit_count: n.audit_count, last_seen: n.last_seen, error: n.error })),
    }),

    // Dashboard
    'GET /dashboard/summary': () => summary(state),
    'GET /dashboard/layout': ({ user }) => ({ layout: state.layouts.get(user.id) || [] }),
    'PUT /dashboard/layout': ({ user, body }) => {
      if (!Array.isArray(body.layout)) throw invalid('layout', 'must be a list')
      state.layouts.set(user.id, body.layout)
      return { layout: body.layout }
    },

    // DNS
    'GET /dns/instances': () => ({
      items: state.nodes.map((n) => ({
        node_id: n.peer.id,
        capabilities: state.dnsCapabilities,
        status: { version: `BIND ${state.dnsCapabilities.version}`, 'number of zones': String(state.zones.length + 100), 'server is up and running': 'yes', 'xfers running': '0', 'recursive clients': '0/900/1000' },
      })),
    }),
    'GET /dns/zones': ({ query }) => {
      const q = (query.get('q') || '').toLowerCase()
      return {
        items: state.zones
          .filter((z) => !query.get('view') || z.view === query.get('view'))
          .filter((z) => !query.get('kind') || z.kind === query.get('kind'))
          .filter((z) => !q || z.name.includes(q))
          // Bulk zone status (additive field, same shape as GET /dns/zones/{zone} status).
          .map((z) => ({ zone: z, mode: zoneMode(z), ...zoneSerials(state, z), status: Object.fromEntries(state.nodes.map((n) => [n.peer.id, zoneStatus(state, z, n.peer.id)])) })),
      }
    },
    'GET /dns/zones/{zone}': ({ params, query }) => {
      const zone = findZone(state, params.zone, query.get('view'))
      const views = [...new Set(state.zones.filter((z) => z.name === zone.name).map((z) => z.view))].sort()
      const copies = Object.fromEntries(
        zoneHolders(state, zone).map((n) => [n.peer.id, { kind: n.is_self || zone.kind !== 'primary' ? zone.kind : 'secondary', source: n.is_self ? zone.source : 'pelagos' }]),
      )
      return { zone, mode: zoneMode(zone), views, status: Object.fromEntries(state.nodes.map((n) => [n.peer.id, zoneStatus(state, zone, n.peer.id)])), copies }
    },
    'POST /dns/zones/{zone}/secondaries/plan': ({ params, body, user }) => {
      const zone = findZone(state, params.zone, body.view)
      if (zone.kind !== 'primary') throw new Problem(409, 'conflict', `${zone.name} is not a primary zone`)
      if (!Array.isArray(body.node_ids)) throw invalid('node_ids', 'list expected')
      const peers = state.nodes.filter((n) => !n.is_self)
      for (const id of body.node_ids) {
        const node = state.nodes.find((n) => n.peer.id === id)
        if (!node) throw invalid('node_ids', id)
        if (node.is_self) throw invalid('node_ids', `${node.peer.name} holds ${zone.name} as primary`)
      }
      const key = `${zone.view}/${zone.name}`
      state.secondaries ||= {}
      const current = state.secondaries[key] || peers.map((n) => n.peer.id)
      const wanted = [...new Set(body.node_ids)]
      const added = wanted.filter((id) => !current.includes(id))
      const removed = current.filter((id) => !wanted.includes(id))
      if (!added.length && !removed.length) throw new Problem(409, 'conflict', `${zone.name} already has exactly these secondaries`)
      const notify = (ids) => ids.map((id) => `192.0.2.${50 + state.nodes.findIndex((n) => n.peer.id === id) + 3}`)
      const changes = [
        { op: 'replace', target: key, before: { also_notify: notify(current) }, after: { also_notify: notify(wanted) }, node_ids: [state.selfId] },
        ...added.map((id) => ({ op: 'add', target: key, before: null, after: { kind: 'secondary', primaries: ['192.0.2.53 key ddi-read'] }, node_ids: [id] })),
        ...removed.map((id) => ({ op: 'delete', target: key, before: { kind: 'secondary' }, after: null, node_ids: [id] })),
      ]
      const names = wanted.map((id) => nodeName(state, id))
      return createPlan(state, user, {
        scope: 'dns.zone',
        engine: 'bind',
        summary: names.length ? `zone ${zone.name}: secondaries on ${names.join(', ')}` : `zone ${zone.name}: no secondary node`,
        changes,
        diff: changes.map((c) => `# ${nodeName(state, c.node_ids[0])}\n${unifiedDiff(jsonText(c.before), jsonText(c.after), `zones.conf ${zone.name}`)}`).join(''),
        targets: [state.selfId, ...added, ...removed],
        tool: 'named-checkconf',
        requires_confirmation: removed.length > 0,
        apply() {
          state.secondaries[key] = wanted
          if (added.length) state.transferLag = { ...(state.transferLag || {}), [zone.name]: Date.now() + (state.transferMs || 0) }
        },
        rollback() {
          state.secondaries[key] = current
        },
      })
    },
    'POST /dns/zones/plan': ({ body, user }) => {
      const change = body.change
      const [view = '_default', name] = String(change?.target || '').split('/')
      // A new primary needs real name servers, as connectors.bind.configplan.initial_ns says.
      if (change?.op === 'add' && change.after?.kind === 'primary') {
        const ns = change.after.ns || []
        if (!ns.length) throw invalid('change.after.ns', `zone ${absName(change.after.name || name)} needs name servers: give ns, or set dns.default_ns in the settings`)
        if (ns.some((n) => n === 'localhost.' || n.endsWith('.localhost.'))) throw invalid('change.after.ns', 'NS localhost. serves the zone to nobody: give the real name servers')
      }
      return listPlan(state, user, {
        scope: 'dns.zone',
        engine: 'bind',
        list: state.zones,
        keyOf: (z) => (z.name ? absName(z.name) : undefined),
        change: { ...change, after: change?.after ? { view, ...change.after, name: absName(change.after.name || name), source: 'pelagos', config_path: '/etc/bind/pelagos/zones.conf' } : null, before: change?.before || (name ? { name } : null) },
        label: 'zone',
        tool: 'named-checkconf',
        targetPrefix: `${view}/`,
        confirm: change?.op === 'delete',
      })
    },
    'GET /dns/zones/{zone}/records': ({ params, query }) => {
      const zone = findZone(state, params.zone, query.get('view'))
      const type = (query.get('type') || '').toUpperCase()
      const name = query.get('name')
      const q = (query.get('q') || '').toLowerCase()
      const items = (state.records[zone.name] || [])
        .filter((r) => !type || r.rtype === type)
        .filter((r) => !name || r.name === absName(name.includes('.') ? name : `${name}.${zone.name}`))
        .filter((r) => !q || r.name.includes(q) || r.rdata.some((d) => d.toLowerCase().includes(q)))
        .sort((a, b) => (a.rtype === 'SOA' ? -1 : b.rtype === 'SOA' ? 1 : a.name.localeCompare(b.name) || a.rtype.localeCompare(b.rtype)))
      return paginate(items, query, { node_id: state.selfId, zone: zone.name, serial: state.soaSerial(state.records[zone.name]) })
    },
    'POST /dns/zones/{zone}/records/plan': ({ params, body, user }) => rrsetPlan(state, user, params.zone, body),
    'POST /dns/ptr/coverage': ({ body }) => {
      if (!Array.isArray(body.addresses)) throw invalid('addresses', 'a list')
      return { items: state.ptr.coverage(body) }
    },
    'GET /dns/ptr/orphans': () => state.ptr.orphans(),
    'POST /dns/ptr/orphans/plan': ({ body, user }) => orphansPlan(state, user, body),
    'POST /dns/zones/{zone}/retransfer': ({ params, body }) => {
      const zone = findZone(state, params.zone, body.view)
      if (zone.kind !== 'secondary') throw new Problem(409, 'conflict', `${zone.name} is not a secondary zone`)
      if (!body.node_id) throw invalid('node_id', 'required')
      return { output: `zone ${zone.name.replace(/\.$/, '')}/IN: retransfer scheduled on ${nodeName(state, body.node_id)}` }
    },
    'POST /dns/zones/{zone}/notify': ({ params, body }) => {
      const zone = findZone(state, params.zone, body.view)
      return { output: `zone notify queued for ${zone.name.replace(/\.$/, '')}` }
    },
    'POST /dns/zones/{zone}/reload': ({ params, body }) => {
      const zone = findZone(state, params.zone, body.view)
      return { output: zone.dynamic ? 'zone reload up-to-date' : 'zone reload queued' }
    },
    'GET /dns/zones/{zone}/dnssec': ({ params, query }) => {
      const zone = findZone(state, params.zone, query.get('view'))
      const signed = Boolean(zone.dnssec_policy)
      return {
        node_id: nodeOr(query),
        status: signed
          ? {
              signed: true,
              policy: zone.dnssec_policy,
              keys: [
                { tag: 48217, role: 'KSK', algorithm: 'ECDSAP256SHA256', state: 'omnipresent', published: iso(Date.now() - 86400000 * 30), next_rollover: null },
                { tag: 9021, role: 'ZSK', algorithm: 'ECDSAP256SHA256', state: 'omnipresent', published: iso(Date.now() - 86400000 * 30), next_rollover: iso(Date.now() + 86400000 * 60) },
              ].map((k) => ({ ...k, id: k.tag, ds_state: k.role === 'KSK' ? 'hidden' : null, goal: 'omnipresent' })),
              ds_guidance: [{ key_id: 48217, action: 'publish', ds: '48217 13 2 4C3F2A8E9D0B1C7F6A5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A', checkds: 'published' }],
              ds: ['48217 13 2 4C3F2A8E9D0B1C7F6A5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A'],
              next_resign: iso(Date.now() + 3600000 * 5),
            }
          : { signed: false, policy: null, keys: [] },
      }
    },
    'GET /dns/config': ({ query }) => bindConfig(state, query.get('node_id')),
    'POST /dns/config/plan': ({ body, user }) => {
      if (!Array.isArray(body.changes) || !body.changes.length) throw invalid('changes', 'at least one change is required')
      const first = body.changes[0]
      if (String(first.target || '').startsWith('handover/')) return handoverPlan(state, user, body)
      // Advanced editor: raw:<file> and several options/<statement> changes in one plan.
      if (body.changes.length > 1 || String(first.target || '').startsWith('raw:')) {
        const text = (c, side) => (typeof c[side] === 'string' ? c[side] : jsonText(c[side]))
        const diff = body.changes
          .map((c) => unifiedDiff(text(c, 'before'), text(c, 'after'), String(c.target).replace(/^raw:\/?/, '')))
          .join('')
        const unbalanced = body.changes.find((c) => {
          const after = text(c, 'after')
          return (after.match(/{/g) || []).length !== (after.match(/}/g) || []).length
        })
        const targets = body.node_ids || state.nodes.map((n) => n.peer.id)
        return createPlan(state, user, {
          scope: 'dns.config',
          engine: 'bind',
          summary: `${body.changes.length} configuration change(s)`,
          changes: body.changes.map((c) => ({ op: c.op || 'replace', target: c.target, before: c.before ?? null, after: c.after ?? null, node_ids: c.node_ids || [] })),
          diff,
          targets,
          validations: targets.map((node_id) => ({
            ok: !unbalanced,
            tool: 'named-checkconf',
            output: unbalanced ? `${String(unbalanced.target).replace(/^raw:/, '')}: missing '}' before end of file` : '',
            node_id,
          })),
          preconditions: targets.map((node_id) => ({ kind: 'config_hash', node_id, subject: 'bind', value: configHash(state, 'bind') })),
          apply: () => {},
          rollback: () => {},
        })
      }
      const statement = String(first.target || '').replace(/^options\//, '')
      const current = bindConfig(state).options.find((o) => o.name === statement)?.value ?? null
      return settingsPlan(state, user, {
        scope: 'dns.config',
        engine: 'bind',
        target: first.target,
        current,
        next: first.after ?? null,
        tool: 'named-checkconf',
        summary: `${body.changes.length} configuration change(s)`,
        apply: () => {},
      })
    },
    'GET /dns/handover': () => ({ items: state.handover.map((i) => ({ ...i, nodes: state.nodes.map((n) => n.peer.id) })) }),
    'GET /dns/keys': () => ({ items: state.keys.map(({ secret: _secret, ...k }) => k) }),
    'GET /dns/keys/{name}/secret': ({ params, user }) => {
      const key = state.keys.find((k) => k.name === params.name)
      if (!key) throw notFound(`key ${params.name}`)
      auditEntry(state, user, { action: 'dns.key.reveal', target: `key:${key.name}`, engine: 'bind' })
      return { name: key.name, algorithm: key.algorithm, secret: key.secret }
    },
    'POST /dns/keys/plan': ({ body, user }) => {
      const change = body.change || {}
      const after = change.after ? { source: 'pelagos', config_path: '/etc/bind/pelagos/keys.conf', used_by: [], ...change.after, secret: change.after.secret || randomBytes(32).toString('base64') } : null
      const plan = listPlan(state, user, {
        scope: 'dns.key', engine: 'bind', list: state.keys, keyOf: (k) => k.name,
        change: { ...change, after }, label: 'key', tool: 'named-checkconf', targetPrefix: 'keys/', confirm: change.op !== 'add',
      })
      // Secrets never leave the server, not even inside a plan.
      for (const c of plan.changes) {
        if (c.before) c.before = { ...c.before, secret: '********' }
        if (c.after) c.after = { ...c.after, secret: '********' }
      }
      plan.diff = unifiedDiff(jsonText(plan.changes[0].before), jsonText(plan.changes[0].after), `key ${plan.changes[0].target}`)
      return plan
    },
    'GET /dns/acls': () => ({ items: state.acls }),
    'POST /dns/acls/plan': ({ body, user }) => listPlan(state, user, {
      scope: 'dns.acl', engine: 'bind', list: state.acls, keyOf: (a) => a.name,
      change: { ...body.change, after: body.change?.after ? { source: 'pelagos', config_path: '/etc/bind/pelagos/acls.conf', ...body.change.after } : null },
      label: 'acl', tool: 'named-checkconf', targetPrefix: 'acls/',
    }),
    'GET /dns/resolver': () => ({
      ...state.resolver,
      per_node: Object.fromEntries(state.nodes.map((n) => [n.peer.id, { ...state.resolver }])),
    }),
    'POST /dns/resolver/plan': ({ body, user }) => {
      // Body keys are the named.conf statement names; the answer of GET uses underscores.
      const keys = ['recursion', 'allow_recursion', 'forwarders', 'forward', 'dnssec_validation']
      const next = { ...state.resolver }
      for (const key of keys) {
        const statement = key.replace(/_/g, '-')
        if (statement in body) next[key] = body[statement]
        else if (key in body) next[key] = body[key]
      }
      return settingsPlan(state, user, {
        scope: 'dns.config', engine: 'bind', target: 'options/resolver', current: state.resolver, next,
        tool: 'named-checkconf', summary: 'update resolver settings',
        apply: (value) => Object.assign(state.resolver, value),
      })
    },
    'GET /dns/rpz': () => ({
      items: [
        { zone: 'rpz.example.lan.', policy: 'given', source: 'user_conf', configured: true },
        { zone: 'feed.rpz.example.', policy: 'nxdomain', source: 'missing', configured: false },
      ],
    }),
    'GET /dns/catalog-zones': () => ({ items: state.catalogs.map((c) => ({ ...c, member_count: c.members.length, error: null })) }),
    'POST /dns/catalog-zones/{zone}/members/plan': ({ params, body, user }) => {
      const catalog = state.catalogs.find((c) => c.zone === absName(params.zone) && c.view === (body.view || '_default'))
      if (!catalog) throw notFound(`catalog zone ${params.zone}`)
      if (!['add', 'delete'].includes(body.op)) throw invalid('op', 'add or delete')
      if (!body.member) throw invalid('member', 'required')
      if (catalog.role !== 'producer') throw invalid('zone', 'members are added on the producer')
      const member = absName(body.member)
      const existing = catalog.members.find((m) => m.zone === member)
      if (body.op === 'add' && existing) throw invalid('member', `${member} is already a member`)
      if (body.op === 'delete' && !existing) throw invalid('member', `${member} is not a member`)
      const label = existing?.label || createHash('sha1').update(member).digest('hex')
      const owner = `${label}.zones.${catalog.zone}`
      const changes = [{ op: body.op, target: `${catalog.zone}/${owner}/PTR`, before: existing ? { name: owner, rtype: 'PTR', ttl: 0, rdata: [member] } : null, after: body.op === 'add' ? { name: owner, rtype: 'PTR', ttl: 0, rdata: [member] } : null, node_ids: [] }]
      const before = JSON.parse(JSON.stringify(catalog.members))
      return createPlan(state, user, {
        scope: 'dns.rrset',
        engine: 'bind',
        summary: `catalog ${catalog.zone}: ${body.op} member ${member}`,
        changes,
        diff: body.op === 'add' ? `+${owner} 0 IN PTR ${member}` : `-${owner} 0 IN PTR ${member}`,
        tool: 'dnspython',
        apply() {
          if (body.op === 'add') catalog.members.push({ zone: member, label, group: body.group || null, coo: null })
          else catalog.members = catalog.members.filter((m) => m.zone !== member)
          return 'NOERROR'
        },
        rollback() {
          catalog.members = before
          return 'NOERROR'
        },
      })
    },
    'GET /dns/dnssec/policies': () => ({
      builtin: ['default', 'insecure', 'none'],
      items: state.dnssecPolicies.map((p) => ({ ...p, used_by: state.zones.filter((z) => z.dnssec_policy === p.name).map((z) => `${z.view}/${z.name}`) })),
    }),
    'POST /dns/dnssec/policies/plan': ({ body, user }) => {
      const change = body.change || {}
      const name = String(change.target || '').replace(/^dnssec-policy\//, '') || change.after?.name
      if (!name) throw invalid('change.target', 'dnssec-policy/<name> is required')
      if (['default', 'insecure', 'none'].includes(name)) throw invalid('change.target', `${name} is a built-in policy`)
      const existing = state.dnssecPolicies.find((p) => p.name === name)
      const statements = change.after?.statements
      if (change.op !== 'delete' && (!Array.isArray(statements) || !statements.length)) throw invalid('change.after.statements', 'non-empty list of {name, value}')
      const text = (p) => (p ? `dnssec-policy "${p.name}" {\n${p.statements.map((s) => `\t${s.name} ${s.value};`).join('\n')}\n};` : '')
      const after = change.op === 'delete' ? null : { name, statements, source: 'pelagos', config_path: '/etc/bind/pelagos/policies.conf', line: 1 }
      const before = JSON.parse(JSON.stringify(state.dnssecPolicies))
      return createPlan(state, user, {
        scope: 'dns.config',
        engine: 'bind',
        summary: `BIND configuration: ${change.op} dnssec-policy/${name}`,
        changes: [{ op: change.op, target: `dnssec-policy/${name}`, before: existing || null, after, node_ids: [] }],
        diff: unifiedDiff(text(existing), text(after), '/etc/bind/pelagos/policies.conf'),
        tool: 'named-checkconf',
        requires_confirmation: change.op === 'delete',
        apply() {
          state.dnssecPolicies = state.dnssecPolicies.filter((p) => p.name !== name)
          if (after) state.dnssecPolicies.push(after)
          return 'reconfig done'
        },
        rollback() {
          state.dnssecPolicies = before
          return 'restored'
        },
      })
    },
    'POST /dns/zones/{zone}/dnssec/plan': ({ params, body, user }) => {
      const zone = findZone(state, params.zone, body.view)
      if (!['rollover', 'checkds'].includes(body.action)) throw invalid('action', 'rollover or checkds')
      if (body.action === 'rollover' && body.key_id === undefined) throw invalid('rollover', 'dnssec-rollover needs key_id')
      if (body.action === 'checkds' && !['published', 'withdrawn'].includes(body.state)) throw invalid('checkds', 'state must be published or withdrawn')
      const name = zone.name.replace(/\.$/, '')
      const command = body.action === 'rollover' ? `rndc dnssec -rollover -key ${body.key_id} ${name}` : `rndc dnssec -checkds ${body.key_id !== undefined ? `-key ${body.key_id} ` : ''}${body.state} ${name}`
      return createPlan(state, user, {
        scope: 'dns.zone',
        engine: 'bind',
        summary: `${zone.name}: ${command}`,
        changes: [{ op: 'replace', target: `op:dnssec-${body.action}/${zone.view}/${zone.name}`, before: null, after: { key_id: body.key_id, state: body.state }, node_ids: [] }],
        diff: `+${command}`,
        tool: 'rndc',
        requires_confirmation: true,
        apply: () => `${command}: done`,
        rollback() {
          throw new Error('an rndc operation cannot be rolled back')
        },
      })
    },
    'GET /dns/stats': ({ query }) => bindStats(state, nodeOr(query)),

    // DHCP
    'GET /dhcp/{family}/servers': ({ params }) => ({
      items: state.nodes.map((n) => ({
        node_id: n.peer.id,
        capabilities: state.dhcpCapabilities[params.family],
        status: { pid: 1200 + (n.is_self ? 1 : 2), uptime: 512000, reload: 3600, 'multi-threading-enabled': true, 'thread-pool-size': 4, enabled: state.serviceEnabled[params.family][n.peer.id] },
        ha: state.ha[params.family].find((h) => h.node_id === n.peer.id) || null,
        config_hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      })),
    }),
    'GET /dhcp/{family}/subnets': ({ params, query }) => {
      const q = (query.get('q') || '').toLowerCase()
      const shared = query.get('shared_network')
      return {
        items: state.subnets[params.family]
          .filter((s) => !shared || s.shared_network === shared)
          .filter((s) => !q || s.subnet.includes(q) || JSON.stringify(s.user_context).toLowerCase().includes(q)),
        utilization: subnetUtilization(state, params.family),
        node_id: state.selfId,
      }
    },
    'GET /dhcp/{family}/subnets/{id}': ({ params }) => {
      const subnet = state.subnets[params.family].find((s) => String(s.id) === params.id)
      if (!subnet) throw notFound(`subnet ${params.id}`)
      return { ...subnet, reservations: state.reservations[params.family].filter((r) => r.subnet_id === subnet.id) }
    },
    'POST /dhcp/{family}/subnets/plan': ({ params, body, user }) => {
      assertFileAgrees(state, params.family)
      const list = state.subnets[params.family]
      const change = body.change || {}
      const after = change.after ? { family: params.family, pools: [], pd_pools: [], options: [], reservations: [], client_classes: [], relay: [], ddns: {}, user_context: {}, raw: {}, ...change.after } : null
      if (after && after.id === undefined) after.id = Math.max(0, ...list.map((s) => s.id)) + 1
      return listPlan(state, user, {
        scope: 'dhcp.subnet', engine: kea(params.family), list, keyOf: (s) => s.id,
        change: { ...change, after }, label: 'subnet', tool: keaTool(params.family),
        targetPrefix: `subnet${params.family === 'v4' ? '4' : '6'}/`, confirm: change.op === 'delete',
      })
    },
    'GET /dhcp/{family}/shared-networks': ({ params }) => ({
      items: state.sharedNetworks[params.family].map((n) => ({ ...n, subnets: state.subnets[params.family].filter((s) => s.shared_network === n.name) })),
    }),
    'POST /dhcp/{family}/shared-networks/plan': ({ params, body, user }) => listPlan(state, user, {
      scope: 'dhcp.shared_network', engine: kea(params.family), list: state.sharedNetworks[params.family], keyOf: (n) => n.name,
      change: { ...body.change, after: body.change?.after ? { family: params.family, subnets: [], options: [], relay: [], user_context: {}, raw: {}, ...body.change.after } : null },
      label: 'shared network', tool: keaTool(params.family), targetPrefix: 'shared-networks/',
    }),
    'GET /dhcp/{family}/client-classes': ({ params }) => ({ items: state.classes[params.family] }),
    'POST /dhcp/{family}/client-classes/plan': ({ params, body, user }) => listPlan(state, user, {
      scope: 'dhcp.class', engine: kea(params.family), list: state.classes[params.family], keyOf: (c) => c.name,
      change: { ...body.change, after: body.change?.after ? { options: [], option_def: [], user_context: {}, raw: {}, ...body.change.after } : null },
      label: 'class', tool: keaTool(params.family), targetPrefix: 'client-classes/',
    }),
    'GET /dhcp/{family}/options': ({ params }) => ({
      items: state.globalOptions[params.family],
      option_defs: [{ name: 'pelagos-site', code: 224, type: 'string', space: params.family === 'v4' ? 'dhcp4' : 'dhcp6', array: false }],
    }),
    'POST /dhcp/{family}/options/plan': ({ params, body, user }) => {
      if (!Array.isArray(body.changes) || !body.changes.length) throw invalid('changes', 'at least one change is required')
      const list = state.globalOptions[params.family]
      const next = JSON.parse(JSON.stringify(list))
      const bad = body.changes.findIndex((c) => !/^option-data\/[^/]+\/[^/]+$/.test(c.target || ''))
      if (bad >= 0) throw new Problem(409, 'conflict', `unknown change target '${body.changes[bad].target}'`)
      for (const c of body.changes) {
        const key = c.after?.name || c.before?.name
        const at = next.findIndex((o) => o.name === key)
        if (c.op === 'delete' && at >= 0) next.splice(at, 1)
        else if (c.op !== 'delete') {
          const value = { space: params.family === 'v4' ? 'dhcp4' : 'dhcp6', csv_format: true, always_send: null, never_send: null, raw: {}, ...c.after }
          if (at >= 0) next[at] = value
          else next.push(value)
        }
      }
      return settingsPlan(state, user, {
        scope: 'dhcp.options', engine: kea(params.family), target: 'option-data', current: list, next,
        tool: keaTool(params.family), summary: `${body.changes.length} option change(s)`,
        apply: (value) => list.splice(0, list.length, ...JSON.parse(JSON.stringify(value))),
      })
    },
    'GET /dhcp/{family}/reservations': ({ params, query }) => {
      const q = (query.get('q') || '').toLowerCase()
      const subnetId = query.get('subnet_id')
      const items = state.reservations[params.family]
        .filter((r) => !subnetId || String(r.subnet_id) === subnetId)
        .filter((r) => !q || [r.identifier, r.ip_address, r.hostname, ...r.ip_addresses].some((v) => v && v.toLowerCase().includes(q)))
      return paginate(items, query, { node_id: state.selfId })
    },
    'POST /dhcp/{family}/reservations/plan': ({ params, body, user }) => {
      const change = body.change || {}
      const after = change.after ? { id_type: 'hw-address', ip_addresses: [], prefixes: [], client_classes: [], options: [], user_context: {}, raw: {}, ...change.after } : null
      const subnetId = (after || change.before || {}).subnet_id
      return listPlan(state, user, {
        scope: 'dhcp.reservation', engine: kea(params.family), list: state.reservations[params.family],
        keyOf: (r) => (r.identifier ? `${r.id_type || 'hw-address'}=${r.identifier}` : undefined),
        change: { ...change, after }, label: 'reservation', tool: keaTool(params.family),
        targetPrefix: subnetId ? `subnet${params.family === 'v4' ? '4' : '6'}/${subnetId}/reservations/` : 'global/reservations/',
      })
    },
    // Cursor pages as Kea gives them (lease-get-page from an address); a search term is an exact lookup.
    'GET /dhcp/{family}/leases': ({ params, query }) => {
      const q = (query.get('q') || '').toLowerCase().trim()
      const subnetId = query.get('subnet_id')
      const stateFilter = query.get('state')
      const limit = Number(query.get('limit') || 100)
      if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw invalid('limit', 'between 1 and 1000')
      const from = query.get('from_address')
      const key = (ip) => ip.split(/[.:]/).map((p) => p.padStart(5, '0')).join('.')
      let items = leasesFor(state, params.family, query.get('node_id'))
        .filter((l) => !subnetId || String(l.subnet_id) === subnetId)
        .sort((a, b) => key(a.ip_address).localeCompare(key(b.ip_address)))
      let next = null
      if (q) {
        items = items.filter((l) => [l.ip_address, l.hw_address, l.hostname?.replace(/\.$/, ''), l.duid].some((v) => v && v.toLowerCase() === q.replace(/\.$/, '')))
      } else {
        if (from) items = items.filter((l) => key(l.ip_address) > key(from))
        if (items.length > limit) next = items[limit - 1].ip_address
        items = items.slice(0, limit)
      }
      items = items.filter((l) => !stateFilter || l.state === stateFilter)
      return { items, page: 1, per_page: limit, total: items.length, meta: { node_id: query.get('node_id') || state.selfId, next, limit } }
    },
    // The collectors' lease watch: newest client transaction first, one copy per address.
    'GET /dhcp/{family}/leases/recent': ({ params, query }) => {
      const limit = Number(query.get('limit') || 20)
      if (!Number.isInteger(limit) || limit < 1 || limit > 50) throw invalid('limit', 'between 1 and 50')
      const best = new Map()
      for (const l of state.leases[params.family]) {
        const held = best.get(l.ip_address)
        if (!held || String(l.cltt) > String(held.cltt)) best.set(l.ip_address, l)
      }
      const items = [...best.values()].sort((a, b) => String(b.cltt).localeCompare(String(a.cltt))).slice(0, limit).map(leaseBrief)
      return { items, as_of: iso(Date.now()), nodes: [...new Set(state.leases[params.family].map((l) => l.node_id))].sort() }
    },
    'GET /dhcp/{family}/leases/{ip}': ({ params }) => {
      const items = state.leases[params.family].filter((l) => l.ip_address === params.ip)
      if (!items.length) throw notFound(`lease ${params.ip}`)
      return { items }
    },
    'POST /dhcp/{family}/leases/{ip}/delete/plan': ({ params, user }) => {
      const list = state.leases[params.family]
      const found = list.filter((l) => l.ip_address === params.ip)
      if (!found.length) throw notFound(`lease ${params.ip}`)
      return createPlan(state, user, {
        scope: 'dhcp.lease',
        engine: kea(params.family),
        summary: `delete lease ${params.ip}`,
        changes: [{ op: 'delete', target: `lease${params.family === 'v4' ? '4' : '6'}/${params.ip}`, before: found[0], after: null, node_ids: [] }],
        diff: unifiedDiff(jsonText(found[0]), '', `lease ${params.ip}`),
        targets: [...new Set(found.map((l) => l.node_id))],
        tool: 'lease_cmds',
        requires_confirmation: true,
        apply() {
          for (const l of found) list.splice(list.indexOf(l), 1)
        },
        rollback() {
          list.push(...found)
        },
      })
    },
    'GET /dhcp/{family}/utilization': ({ params, query }) => ({ items: utilization(state, params.family, query.get('node_id')) }),
    'GET /dhcp/{family}/stats': ({ params, query }) => {
      const items = utilization(state, params.family, query.get('node_id'))
      const node = nodeOr(query)
      const scale = node === state.selfId ? 1 : 0.15
      const live = params.family === 'v6'
        ? liveCounters(`${node}/v6`, { 'pkt6-received': [40110, 6 * scale], 'pkt6-solicit-received': [9020, 1.5 * scale], 'pkt6-advertise-sent': [9011, 1.5 * scale], 'pkt6-request-received': [18030, 2.6 * scale], 'pkt6-reply-sent': [26044, 2.6 * scale] })
        : liveCounters(`${node}/v4`, { 'pkt4-received': [120220, 14 * scale], 'pkt4-discover-received': [30110, 3.2 * scale], 'pkt4-offer-sent': [30101, 3.15 * scale], 'pkt4-request-received': [70210, 6.5 * scale], 'pkt4-ack-sent': [70011, 6.4 * scale], 'pkt4-nak-sent': [12, 0.02 * scale] })
      const counters = params.family === 'v6'
        ? { ...live, 'pkt6-receive-drop': 1 }
        : { ...live, 'pkt4-receive-drop': 3 }
      items.forEach((r, i) => {
        counters[`subnet[${r.subnet_id}].pool[${i}].total-addresses`] = r.total
        counters[`subnet[${r.subnet_id}].pool[${i}].assigned-addresses`] = r.assigned
        counters[`subnet[${r.subnet_id}].pool[${i}].declined-addresses`] = r.declined
      })
      // Kea statistic-get-all: each value is a list of [value, "YYYY-MM-DD hh:mm:ss.ffffff"] samples.
      const stamp = iso(Date.now()).replace('T', ' ').replace('Z', '000')
      const statistics = Object.fromEntries(Object.entries(counters).map(([k, v]) => [k, [[v, stamp]]]))
      return { node_id: nodeOr(query), statistics }
    },
    'GET /dhcp/{family}/ha': ({ params }) => ({ items: state.ha[params.family].map((h) => liveHa(h)), relationships: haRelationships(state, params.family) }),
    'POST /dhcp/{family}/ha/setup/plan': ({ params, body, user }) => {
      const ha = state.ha[params.family]
      if (body.remove === true) {
        const before = ha.map((h) => ({ ...h }))
        return createPlan(state, user, {
          scope: 'dhcp.config',
          engine: kea(params.family),
          summary: `${kea(params.family)}: remove HA from ${ha.map((h) => nodeName(state, h.node_id)).join(', ')}`,
          changes: ha.map((h) => ({ op: 'replace', target: 'hooks-libraries', before: 'ha', after: null, node_ids: [h.node_id] })),
          diff: ha.map((h) => `# ${nodeName(state, h.node_id)}\n-libdhcp_ha.so (${h.server_name})\n`).join(''),
          targets: ha.map((h) => h.node_id),
          tool: 'config-test',
          requires_confirmation: true,
          apply() {
            ha.forEach((h) => Object.assign(h, { enabled: false, state: null, partner: null, peers: [] }))
          },
          rollback() {
            ha.splice(0, ha.length, ...before)
          },
        })
      }
      // One relationship ({mode, servers}) or several ({relationships}: Kea 3 hub and spoke).
      const multi = Array.isArray(body.relationships)
      const rels = multi ? body.relationships : [body]
      if (multi && !rels.length) throw invalid('relationships', 'a list of relationships, each with mode and servers')
      const errors = []
      const names = new Set()
      const urls = new Set()
      rels.forEach((rel, r) => {
        const at = multi ? `relationships[${r}].` : ''
        const roles = HA_MODE_ROLES[rel.mode]
        if (!roles) {
          errors.push({ field: `${at}mode`, message: 'hot-standby, load-balancing or passive-backup' })
          return
        }
        const servers = Array.isArray(rel.servers) ? rel.servers : []
        if (servers.length < 2) {
          errors.push({ field: `${at}servers`, message: 'at least two servers' })
          return
        }
        const counts = {}
        const nodes = new Set()
        servers.forEach((srv, i) => {
          if (!srv.name || /\s/.test(srv.name)) errors.push({ field: `${at}servers[${i}].name`, message: 'a name without spaces' })
          else if (names.has(srv.name)) errors.push({ field: `${at}servers[${i}].name`, message: multi ? 'a server name is used in one relationship only' : 'duplicate name' })
          names.add(srv.name)
          if (!/^https?:\/\/[^/]+/.test(srv.url || '')) errors.push({ field: `${at}servers[${i}].url`, message: 'http://address:port/ or https://address:port/' })
          else if (urls.has(srv.url)) errors.push({ field: `${at}servers[${i}].url`, message: multi ? 'each relationship needs its own url' : 'duplicate url' })
          urls.add(srv.url)
          if (!roles[srv.role]) errors.push({ field: `${at}servers[${i}].role`, message: `${rel.mode} takes ${Object.keys(roles).join(', ')}` })
          else counts[srv.role] = (counts[srv.role] || 0) + 1
          if (srv.node_id) {
            if (nodes.has(srv.node_id)) errors.push({ field: `${at}servers[${i}].node_id`, message: 'a node runs one server of the relationship' })
            nodes.add(srv.node_id)
          }
        })
        for (const [role, [low, high]] of Object.entries(roles)) {
          const n = counts[role] || 0
          if (n < low || n > high) errors.push({ field: `${at}servers`, message: `${rel.mode} needs ${low === high ? low : `at least ${low}`} ${role} server(s), got ${n}` })
        }
      })
      const placed = rels.flatMap((rel) => (rel.servers || []).filter((srv) => srv.node_id).map((srv) => ({ rel, srv })))
      if (!errors.length && !placed.length) errors.push({ field: multi ? 'relationships[].servers[].node_id' : 'servers[].node_id', message: 'required' })
      if (errors.length) throw new Problem(400, 'validation_error', `invalid HA setup: ${errors[0].field}: ${errors[0].message}`, errors)
      const nodeIds = [...new Set(placed.map((x) => x.srv.node_id))]
      const peersOf = (rel) => rel.servers.map(({ name, url, role }) => ({ name, url, role, auto_failover: null }))
      const entriesOf = (nodeId) => placed.filter((x) => x.srv.node_id === nodeId).map(({ rel, srv }) => ({ 'this-server-name': srv.name, mode: rel.mode, peers: peersOf(rel) }))
      const before = ha.map((h) => ({ ...h }))
      const all = rels.flatMap((rel) => rel.servers)
      return createPlan(state, user, {
        scope: 'dhcp.config',
        engine: kea(params.family),
        summary: `${kea(params.family)} HA ${[...new Set(rels.map((rel) => rel.mode))].join(', ')} on ${all.length} servers: ${all.map((srv) => `${srv.name} (${srv.role})`).join(', ')}`,
        changes: nodeIds.map((nodeId) => ({ op: 'replace', target: 'hooks-libraries', before: null, after: entriesOf(nodeId), node_ids: [nodeId] })),
        diff: nodeIds.map((nodeId) => `# ${nodeName(state, nodeId)}\n${unifiedDiff('', jsonText(entriesOf(nodeId)), 'hooks-libraries')}`).join(''),
        targets: nodeIds,
        tool: 'config-test',
        requires_confirmation: true,
        apply() {
          const stateOf = ({ rel, srv }) => {
            const prev = before.find((h) => h.node_id === srv.node_id) || {}
            const backup = srv.role === 'backup'
            const other = rel.servers.find((o) => o !== srv && o.role !== 'backup')
            return {
              ...prev,
              node_id: srv.node_id,
              family: params.family,
              collected_at: iso(Date.now()),
              server_name: srv.name,
              mode: rel.mode,
              role: srv.role,
              state: backup ? 'backup' : rel.mode === 'passive-backup' ? 'passive-backup' : rel.mode,
              scopes: srv.role === 'primary' ? [srv.name] : [],
              unsent_update_count: 0,
              peers: peersOf(rel),
              partner: backup || !other ? null : { role: other.role, server_name: other.name, state: rel.mode, scopes: [], in_touch: true, last_state: rel.mode, age: 1 },
              enabled: true,
              raw: {},
              other_relationships: [],
            }
          }
          const next = nodeIds.map((nodeId) => {
            const [first, ...more] = placed.filter((x) => x.srv.node_id === nodeId).map(stateOf)
            return { ...first, other_relationships: more }
          })
          ha.splice(0, ha.length, ...next)
          next.forEach((h) => emit('ha', 'state', h))
        },
        rollback() {
          ha.splice(0, ha.length, ...before)
        },
      })
    },
    'POST /dhcp/{family}/ha/maintenance/plan': ({ params, body, user }) => {
      if (!['start', 'cancel'].includes(body.action)) throw invalid('action', 'must be start or cancel')
      const ha = state.ha[params.family]
      const target = ha.find((h) => h.node_id === body.node_id)
      if (!target) throw notFound(`HA server on node ${body.node_id}`)
      const held = [target, ...(target.other_relationships || [])]
      if (held.every((h) => h.role === 'backup')) throw invalid('node_id', `${nodeName(state, body.node_id)} is an HA backup server: it takes no part in HA maintenance, stop it directly`)
      // The server that stays up is the partner by server name, never a backup; a hub has one per relationship.
      const flat = flatHa(ha)
      const partners = held
        .filter((h) => h.role !== 'backup')
        .map((h) => flat.find((o) => o.server_name === h.partner?.server_name) || flat.find((o) => o.node_id !== h.node_id && o.role !== 'backup'))
        .filter(Boolean)
      const ups = [...new Set(partners.map((p) => p.node_id))]
      const snapshot = () => flat.map((h) => ({ h, state: h.state }))
      const before = snapshot()
      return createPlan(state, user, {
        scope: 'dhcp.ha',
        engine: kea(params.family),
        summary: `${body.action === 'start' ? 'start' : 'cancel'} HA maintenance on ${nodeName(state, body.node_id)}`,
        changes: [{ op: 'replace', target: `ha/${nodeName(state, body.node_id)}`, before: target.state, after: body.action === 'start' ? 'in-maintenance' : 'hot-standby', node_ids: ups.length ? ups : [body.node_id] }],
        diff: unifiedDiff(`state: ${target.state}`, `state: ${body.action === 'start' ? 'in-maintenance' : 'hot-standby'}`, `ha ${nodeName(state, body.node_id)}`),
        targets: ups.length ? ups : [body.node_id],
        tool: body.action === 'start' ? 'ha-maintenance-start' : 'ha-maintenance-cancel',
        requires_confirmation: true,
        preconditions: [{ kind: 'ha_state', node_id: body.node_id, subject: 'ha', value: target.state }],
        apply() {
          const start = body.action === 'start'
          for (const h of held) if (h.role !== 'backup') h.state = start ? 'in-maintenance' : h.mode
          for (const p of partners) p.state = start ? 'partner-in-maintenance' : p.mode
          ha.forEach((h) => emit('ha', 'state', h))
        },
        rollback() {
          for (const b of before) b.h.state = b.state
        },
      })
    },
    // As the backend: node clocks checked, then the HA service of each server restarted in turn (primary last).
    'POST /dhcp/{family}/ha/repair/plan': ({ params, user }) => {
      const flat = flatHa(state.ha[params.family])
      const stuck = flat.filter((h) => h.state === 'terminated')
      if (!stuck.length) throw new Problem(409, 'conflict', 'no HA server is in the terminated state')
      const involved = flat.filter((h) => h.role !== 'backup' && stuck.some((s) => s.server_name === h.server_name || s.partner?.server_name === h.server_name))
      involved.sort((a, b) => (a.role === 'primary') - (b.role === 'primary'))
      const order = [...new Set(involved.map((h) => h.node_id))]
      const validations = order.map((id) => {
        const clock = state.nodes.find((n) => n.peer.id === id)?.clock
        const offset = Number(clock?.offset ?? 0)
        const ok = Math.abs(offset) - Number(clock?.uncertainty ?? 0) < (setting(state, 'checks.clock_skew_warning_seconds') ?? 5)
        const sign = offset >= 0 ? '+' : '-'
        return { ok, tool: 'clock', node_id: id, output: `${nodeName(state, id)}: clock ${sign}${Math.abs(offset).toFixed(1)} s${ok ? '' : ': synchronize the clocks (NTP) first'}` }
      })
      const servers = involved.map((h) => `${h.server_name} (${nodeName(state, h.node_id)})`).join(', ')
      const before = involved.map((h) => ({ h, state: h.state, partner: { ...h.partner } }))
      return createPlan(state, user, {
        scope: 'dhcp.ha',
        engine: kea(params.family),
        summary: `repair ${kea(params.family)} HA: restart the HA service of ${servers} one after the other`,
        summary_message: { key: 'plan.kea.ha_repair', params: { engine: kea(params.family), servers } },
        changes: [{ op: 'replace', target: 'ha/restart', before: Object.fromEntries(involved.map((h) => [h.node_id, h.state])), after: { action: 'restart', order }, node_ids: order }],
        diff: involved.map((h) => `-${h.server_name}: ${h.state}\n`).join('') + order.map((id, i) => `+${i + 1}. ${nodeName(state, id)}: restart HA (config-reload)\n`).join(''),
        targets: order,
        validations,
        requires_confirmation: true,
        apply() {
          for (const h of involved) {
            h.state = h.mode
            h.partner = { ...h.partner, state: h.mode, in_touch: true, age: 0, clock_skew: 0 }
          }
          for (const a of state.alerts) {
            if (a.kind === 'ha_terminated' && a.engine === kea(params.family) && a.state !== 'resolved') {
              a.state = 'resolved'
              a.resolved_at = iso(Date.now())
              emit('alerts', 'resolved', a)
            }
          }
          involved.forEach((h) => emit('ha', 'state', h))
        },
        rollback() {
          // A restart is not undone: nothing changes.
          return before.length
        },
      })
    },
    'GET /dhcp/{family}/ha/transitions': ({ params }) => ({ items: haTransitions(state, params.family) }),
    'POST /dhcp/{family}/service/plan': ({ params, body, user }) => {
      if (typeof body.enable !== 'boolean') throw invalid('enable', 'must be a boolean')
      const map = state.serviceEnabled[params.family]
      if (!(body.node_id in map)) throw notFound(`node ${body.node_id}`)
      const before = map[body.node_id]
      return createPlan(state, user, {
        scope: 'dhcp.ha',
        engine: kea(params.family),
        summary: `${body.enable ? 'enable' : 'disable'} DHCP service on ${nodeName(state, body.node_id)}`,
        changes: [{ op: 'replace', target: `service/${nodeName(state, body.node_id)}`, before, after: body.enable, node_ids: [body.node_id] }],
        diff: unifiedDiff(`enabled: ${before}`, `enabled: ${body.enable}`, `service ${nodeName(state, body.node_id)}`),
        targets: [body.node_id],
        tool: body.enable ? 'dhcp-enable' : 'dhcp-disable',
        requires_confirmation: true,
        apply: () => { map[body.node_id] = body.enable },
        rollback: () => { map[body.node_id] = before },
      })
    },
    'GET /dhcp/{family}/ddns': ({ params }) => ({ ...state.ddns[params.family], node_id: state.selfId }),
    'POST /dhcp/{family}/ddns/plan': ({ params, body, user }) => {
      if (!Array.isArray(body.changes) || !body.changes.length) throw invalid('changes', 'at least one change is required')
      const current = state.ddns[params.family].ddns_params
      const next = { ...current }
      for (const c of body.changes) {
        if (c.op === 'delete') delete next[c.target]
        else next[c.target] = c.after
      }
      return settingsPlan(state, user, {
        scope: 'dhcp.ddns', engine: kea(params.family), target: 'ddns-params', current, next,
        tool: keaTool(params.family), summary: `${body.changes.length} DDNS change(s)`,
        apply: (value) => { state.ddns[params.family].ddns_params = { ...value } },
      })
    },
    'GET /dhcp/{family}/hooks': ({ params }) => ({ items: state.hooks[params.family], available: state.availableHooks }),
    'POST /dhcp/{family}/hooks/plan': ({ params, body, user }) => {
      if (!Array.isArray(body.changes) || !body.changes.length) throw invalid('changes', 'at least one change is required')
      const list = state.hooks[params.family]
      const next = body.changes[0].after || list
      if (!Array.isArray(next)) throw invalid('changes[0].after', 'must be the full hooks-libraries list')
      return settingsPlan(state, user, {
        scope: 'dhcp.options', engine: kea(params.family), target: 'hooks-libraries', current: list, next,
        tool: keaTool(params.family), summary: 'update hooks-libraries',
        apply: (value) => list.splice(0, list.length, ...value.map((h) => ({ parameters: {}, known: true, name: String(h.library).replace(/^.*libdhcp_|\.so$/g, ''), ...h }))),
      })
    },
    'GET /dhcp/{family}/config': ({ params, query }) => ({
      node_id: nodeOr(query),
      hash: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
      config: bareKea(keaConfig(state, params.family)),
    }),
    'POST /dhcp/{family}/config/plan': ({ params, body, user }) => {
      if (!body.config || typeof body.config !== 'object') throw invalid('config', 'required')
      assertFileAgrees(state, params.family)
      const current = bareKea(keaConfig(state, params.family))
      const root = params.family === 'v4' ? 'Dhcp4' : 'Dhcp6'
      const sent = body.config[root] ?? body.config
      const ok = Boolean(sent) && typeof sent === 'object' && !Array.isArray(sent)
      const plan = createPlan(state, user, {
        scope: 'dhcp.config',
        engine: kea(params.family),
        summary: 'replace the whole configuration',
        changes: [{ op: 'replace', target: 'config', before: current, after: body.config, node_ids: body.node_ids || [] }],
        diff: unifiedDiff(jsonText(current), jsonText(body.config), `kea-dhcp${params.family === 'v4' ? '4' : '6'}.conf`),
        targets: body.node_ids || state.nodes.map((n) => n.peer.id),
        validations: (body.node_ids || state.nodes.map((n) => n.peer.id)).map((node_id) => ({
          ok,
          tool: 'config-test',
          output: ok ? 'Configuration seems sane.' : `missing top-level "${root}" object`,
          node_id,
        })),
        preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: kea(params.family), value: configHash(state, kea(params.family)) })),
        apply: () => 'config-set and config-write done',
        rollback: () => {},
      })
      return plan
    },
    'GET /dhcp/d2/servers': () => ({
      items: state.nodes.map((n) => ({ node_id: n.peer.id, capabilities: capabilities(state).engines.d2, status: { pid: 1300, uptime: 512000 } })),
    }),
    'GET /dhcp/d2/stats': ({ query }) => state.d2[nodeOr(query)] || (() => { throw notFound('D2 on this node') })(),
    'GET /dhcp/d2/config': ({ query }) => ({ node_id: nodeOr(query), config: bareKea(d2Config()) }),
    'GET /dhcp/{family}/config/file': ({ params }) => ({ items: [fileStatus(state, params.family)] }),
    'POST /dhcp/{family}/config/adopt/plan': ({ params, body, user }) => adoptPlan(state, user, params.family, body),
    'GET /dhcp/d2/config/file': () => ({ items: [fileStatus(state, 'd2')] }),
    'POST /dhcp/d2/config/adopt/plan': ({ body, user }) => adoptPlan(state, user, 'd2', body),
    'POST /dhcp/d2/config/plan': ({ body, user }) => {
      if (!body.config || typeof body.config !== 'object') throw invalid('config', 'required')
      assertFileAgrees(state, 'd2')
      return createPlan(state, user, {
        scope: 'd2.config',
        engine: 'd2',
        summary: 'replace the D2 configuration',
        changes: [{ op: 'replace', target: 'config', before: bareKea(d2Config()), after: body.config, node_ids: body.node_ids || [] }],
        diff: unifiedDiff(jsonText(bareKea(d2Config())), jsonText(body.config), 'kea-dhcp-ddns.conf'),
        targets: body.node_ids || state.nodes.map((n) => n.peer.id),
        tool: 'config-test',
        apply: () => 'applied',
        rollback: () => {},
      })
    },

    // Hosts
    'GET /hosts': ({ query }) => {
      const q = (query.get('q') || '').toLowerCase()
      const subnetId = query.get('subnet_id')
      const zone = query.get('zone')
      const onlyBad = query.get('only_inconsistent') === 'true'
      const items = buildHosts(state)
        .filter((h) => !q || [h.key, h.mac, h.hostname, ...h.ips].some((v) => v && v.toLowerCase().includes(q)))
        .filter((h) => !subnetId || String(h.lease?.subnet_id ?? h.reservation?.subnet_id) === subnetId)
        .filter((h) => !zone || (h.hostname || '').endsWith(absName(zone)))
        .filter((h) => !onlyBad || h.alerts.length > 0)
      return paginate(items, query, { node_id: state.selfId })
    },
    'GET /hosts/{key}': ({ params }) => {
      const host = buildHosts(state).find((h) => h.key === params.key || h.ips.includes(params.key) || h.mac === params.key)
      if (!host) throw notFound(`host ${params.key}`)
      return host
    },
    'POST /hosts/plan': ({ body, user }) => {
      const errors = []
      const ip = String(body.ip || '').trim().toLowerCase()
      const v6 = ip.includes(':')
      if (!body.hostname) errors.push({ field: 'hostname', message: 'required' })
      if (!(v6 ? /^[0-9a-f:]+$/.test(ip) && ip.split('::').length <= 2 && v6Nibbles(ip).length === 32 : /^(\d{1,3}\.){3}\d{1,3}$/.test(ip))) {
        errors.push({ field: 'ip', message: 'a valid IPv4 or IPv6 address is required' })
      }
      if (body.reservation && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(body.mac || '')) errors.push({ field: 'mac', message: 'required for a reservation' })
      if (errors.length) throw new Problem(400, 'validation_error', 'invalid host request', errors)
      const family = v6 ? 'v6' : 'v4'
      const rtype = v6 ? 'AAAA' : 'A'
      const address = v6 ? canonicalV6(v6Nibbles(ip)) : ip
      const zone = absName(body.zone || 'example.lan')
      const fqdn = absName(body.hostname.includes('.') ? body.hostname : `${body.hostname}.${zone}`)
      const ttl = Number(body.ttl ?? 300)
      const records = state.records[zone]
      if (!records) throw notFound(`zone ${zone}`)
      // Reverse pointer of the address; the PTR goes in the longest reverse zone holding it.
      const ptrName = v6
        ? `${v6Nibbles(address).split('').reverse().join('.')}.ip6.arpa.`
        : `${address.split('.').reverse().join('.')}.in-addr.arpa.`
      // As the backend: an absent reverse_view follows view, and the PTR zone is looked up there.
      const view = body.view || '_default'
      const reverseView = body.reverse_view || view
      const reverseZone = body.reverse_zone
        ? absName(body.reverse_zone)
        : state.zones
            .filter((z) => z.kind === 'primary' && z.view === reverseView && z.name.endsWith('.arpa.') && ptrName.endsWith(`.${z.name}`))
            .map((z) => z.name)
            .sort((a, b) => b.length - a.length)[0]
      const reverse = (reverseZone && state.records[reverseZone]) || null
      const subnetId = body.subnet_id ?? state.subnets[family][0]?.id ?? 1
      const reservation = body.reservation
        ? {
            subnet_id: subnetId,
            id_type: 'hw-address',
            identifier: body.mac.toLowerCase(),
            ip_address: v6 ? null : address,
            ip_addresses: v6 ? [address] : [],
            prefixes: [],
            hostname: fqdn.replace(/\.$/, ''),
            client_classes: [],
            options: [],
            next_server: null,
            server_hostname: null,
            boot_file_name: null,
            user_context: body.notes ? { pelagos: { notes: body.notes, updated_by: user.username } } : {},
            raw: {},
          }
        : null
      const forward = { name: fqdn, rtype, ttl, rdata: [address] }
      const ptr = reverse ? { name: ptrName, rtype: 'PTR', ttl, rdata: [fqdn] } : null
      const changes = [
        { op: 'add', target: `${zone}/${fqdn}/${rtype}`, before: null, after: forward, node_ids: [] },
        ...(ptr ? [{ op: 'add', target: `${reverseZone}/${ptrName}/PTR`, before: null, after: ptr, node_ids: [] }] : []),
        ...(reservation ? [{ op: 'add', target: `subnet${v6 ? 6 : 4}/${subnetId}/reservations/hw-address=${reservation.identifier}`, before: null, after: reservation, node_ids: [] }] : []),
      ]
      const text = changes.map((c) => (c.after.rtype ? rrsetText(c.after) : jsonText(c.after))).join('\n')
      return createPlan(state, user, {
        scope: 'host',
        engine: null,
        summary: `host ${fqdn} -> ${address}${view !== '_default' || reverseView !== view ? ` (view ${view}, PTR in ${reverseView})` : ''}${reservation ? ` reserved for ${reservation.identifier}` : ''}`,
        changes,
        diff: unifiedDiff('', text, `host ${fqdn}`),
        targets: state.nodes.map((n) => n.peer.id),
        validations: [
          { ok: true, tool: 'dnspython', output: '', node_id: state.selfId },
          ...(reservation ? [{ ok: true, tool: `kea-dhcp${v6 ? 6 : 4} -t`, output: '', node_id: state.selfId }] : []),
        ],
        preconditions: [{ kind: 'rrset_absent', node_id: state.selfId, subject: `${zone}/${fqdn}/${rtype}`, value: '' }],
        apply() {
          records.push(forward)
          bumpSerial(records)
          if (ptr) {
            reverse.push(ptr)
            bumpSerial(reverse)
          }
          if (reservation) state.reservations[family].push(reservation)
        },
        rollback() {
          records.splice(records.indexOf(forward), 1)
          if (ptr) reverse.splice(reverse.indexOf(ptr), 1)
          if (reservation) state.reservations[family].splice(state.reservations[family].indexOf(reservation), 1)
        },
      })
    },

    // Plans and jobs
    'GET /plans/{id}': ({ params, user }) => {
      const held = ownPlan(params.id, user)
      if (held.plan.state === 'validated' && isExpired(held.plan)) held.plan.state = 'expired'
      return held.plan
    },
    // With applyNodeMs set, a plan takes time like the real one: this node applies (its audit
    // entry goes out), then each peer, then the ApplyResult. A rollback runs peers first.
    'POST /plans/{id}/apply': async ({ params, body, user, res }) => {
      const pace = state.applyNodeMs || 0
      const job = Boolean(state.plans.get(params.id)?.job)
      const queued = []
      const out = applyPlan(state, user, params.id, Boolean(body.confirm), pace && !job ? (...a) => queued.push(a) : emit)
      if (out.code) throw new Problem(out.status, out.code, out.detail)
      if (queued.length) {
        await replayPaced(queued, pace, emit)
        markTransfer(params.id)
      }
      res.statusCode = out.status
      return out.body
    },
    'POST /plans/{id}/rollback': async ({ params, user }) => {
      const pace = state.applyNodeMs || 0
      const queued = []
      const out = rollbackPlan(state, user, params.id, pace ? (...a) => queued.push(a) : emit)
      if (out.code) throw new Problem(out.status, out.code, out.detail)
      if (pace) {
        await replayPaced(queued, pace, emit)
        markTransfer(params.id)
      }
      return out.body
    },
    'DELETE /plans/{id}': ({ params, user }) => {
      ownPlan(params.id, user)
      state.plans.delete(params.id)
      return null
    },
    'GET /jobs/{id}': ({ params }) => state.jobs.get(params.id) || (() => { throw notFound(`job ${params.id}`) })(),

    // Alerts and series
    'GET /alerts': ({ query }) => {
      const f = (key, value) => !query.get(key) || value === query.get(key)
      // A node's alerts plus the cluster-wide ones it reports; alerts of unreadable nodes are missing.
      const onNode = (a) => !query.get('node_id') || a.node_id === query.get('node_id') || (!a.node_id && (a.reported_by || []).includes(query.get('node_id')))
      const items = visibleAlerts(state).filter((a) => f('kind', a.kind) && f('severity', a.severity) && f('state', a.state) && onNode(a) && f('engine', a.engine))
      return paginate(items, query, { unavailable: state.alertsUnavailable || [] })
    },
    'GET /alerts/summary': () => {
      const alerts = visibleAlerts(state)
      const open = alerts.filter((a) => a.state === 'open')
      const count = (list, key) => list.reduce((acc, a) => ({ ...acc, [a[key]]: (acc[a[key]] || 0) + 1 }), {})
      return { open: open.length, acked: alerts.filter((a) => a.state === 'acked').length, by_severity: count(open, 'severity'), by_kind: count(open, 'kind'), unavailable: state.alertsUnavailable || [] }
    },
    'POST /alerts/{id}/ack': ({ params, body, user }) => {
      const alert = state.alerts.find((a) => a.id === params.id)
      if (!alert) throw notFound(`alert ${params.id}`)
      if (alert.state === 'resolved') throw new Problem(409, 'conflict', 'alert already resolved')
      alert.state = 'acked'
      alert.acked_by = user.username
      alert.acked_at = iso(Date.now())
      const entry = auditEntry(state, user, { action: 'alert.ack', target: `alert:${alert.id}`, message: body.comment || null })
      emit('alerts', 'acked', alert)
      emit('audit', 'entry', entry)
      return alert
    },
    'GET /alerts/exceptions': ({ query }) => ({ items: state.ptr.exceptions().filter((e) => !query.get('kind') || e.kind === query.get('kind')) }),
    'POST /alerts/exceptions': ({ body, user, res }) => {
      const errors = []
      if (!EXCEPTION_KINDS.has(body.kind)) errors.push({ field: 'kind', message: 'an alert kind that accepts exceptions' })
      if (!body.key || typeof body.key !== 'string') errors.push({ field: 'key', message: 'required' })
      if (!String(body.comment || '').trim()) errors.push({ field: 'comment', message: 'required: say why the object is left as it is' })
      if (errors.length) throw new Problem(400, 'validation_error', 'invalid exception', errors)
      const list = state.ptr.exceptions()
      if (list.some((e) => e.kind === body.kind && e.key === body.key)) throw new Problem(409, 'conflict', `${body.kind} ${body.key} is already an exception`)
      const record = { id: ulid(), kind: body.kind, key: body.key, comment: String(body.comment).trim(), created_by: user.username, created_at: iso(Date.now()), node_id: state.selfId, ...(body.summary ? { summary: body.summary } : {}) }
      list.push(record)
      // As the collector's next pass: an alert whose every object is excepted resolves.
      for (const a of state.alerts) {
        const keys = a.details?.exception_keys || []
        if (a.kind === record.kind && a.state !== 'resolved' && keys.length && keys.every((k) => list.some((e) => e.kind === a.kind && e.key === k))) {
          a.state = 'resolved'
          a.resolved_at = iso(Date.now())
          emit('alerts', 'resolved', a)
        }
      }
      emit('audit', 'entry', auditEntry(state, user, { action: 'alert.exception.add', target: `exception:${record.kind}:${record.key}`, message: record.comment }))
      res.statusCode = 201
      return record
    },
    'DELETE /alerts/exceptions/{id}': ({ params, user }) => {
      const list = state.ptr.exceptions()
      const idx = list.findIndex((e) => e.id === params.id)
      if (idx < 0) throw notFound(`exception ${params.id}`)
      const [record] = list.splice(idx, 1)
      emit('audit', 'entry', auditEntry(state, user, { action: 'alert.exception.revoke', target: `exception:${record.kind}:${record.key}` }))
      return null
    },
    'POST /alerts/consistency/run': ({ res }) => {
      const job = { id: ulid(), plan_id: null, state: 'running', progress: 10, steps: [{ name: 'consistency', state: 'running', output: '', started_at: iso(Date.now()), finished_at: null }], created_at: iso(Date.now()), finished_at: null, error: null }
      state.jobs.set(job.id, job)
      const timer = setTimeout(() => {
        job.state = 'done'
        job.progress = 100
        job.steps[0].state = 'done'
        // Like the jobs service: the runner's return value becomes a final "result" step.
        const found = state.alerts.filter((x) => INCONSISTENCY_KINDS.has(x.kind) && x.state !== 'resolved')
        const byKind = {}
        for (const x of found) byKind[x.kind] = (byKind[x.kind] || 0) + 1
        job.steps.push({ name: 'result', state: 'done', output: { found: found.length, by_kind: byKind, alerts: found, errors: {}, collector_signalled: true }, started_at: job.finished_at, finished_at: iso(Date.now()) })
        job.finished_at = iso(Date.now())
        emit('jobs', 'done', job)
      }, 500)
      timer.unref?.()
      res.statusCode = 202
      return { job_id: job.id }
    },
    'GET /series/pools': ({ query }) => seriesPools(state, query),
    'GET /series/serials': ({ query }) => {
      const zoneName = absName(query.get('zone') || 'example.lan')
      const zone = findZone(state, zoneName)
      const to = parseTime(query.get('to')) || Date.now()
      const from = parseTime(query.get('from')) || to - 86400000
      const { serials } = zoneSerials(state, zone)
      return {
        series: state.nodes.map((n) => {
          const points = []
          for (let t = from, i = 0; t <= to; t += 3600000, i += 1) {
            const serial = (serials[n.peer.id] ?? 0) - Math.floor((to - t) / 14400000)
            points.push([Math.floor(t / 1000), serial, n.is_self ? false : zone.name === 'lab.example.lan.'])
          }
          return { node_id: n.peer.id, points }
        }),
      }
    },
    'GET /series/ha-transitions': ({ query }) => {
      const family = query.get('engine') === 'kea6' ? 'v6' : 'v4'
      const nodeId = query.get('node_id')
      return { items: haTransitions(state, family).filter((t) => !nodeId || t.node_id === nodeId) }
    },

    // Audit
    'GET /audit': ({ query }) => {
      const f = (key, value) => !query.get(key) || value === query.get(key)
      const from = parseTime(query.get('from'))
      const to = parseTime(query.get('to'))
      const action = query.get('action')
      const target = query.get('target')
      const items = state.audit.filter(
        (e) =>
          f('user', e.user) && f('node_id', e.node_id) && f('engine', e.engine) && f('result', e.result) &&
          (!action || e.action.startsWith(action)) && (!target || e.target.includes(target)) &&
          (!from || Date.parse(e.ts) >= from) && (!to || Date.parse(e.ts) <= to),
      )
      return paginate(items, query)
    },
    'GET /audit/{id}': ({ params }) => state.audit.find((e) => e.id === params.id) || (() => { throw notFound(`audit entry ${params.id}`) })(),
    'GET /audit/export': ({ query, res }) => {
      const from = parseTime(query.get('from'))
      const to = parseTime(query.get('to'))
      const lines = state.audit.filter((e) => (!from || Date.parse(e.ts) >= from) && (!to || Date.parse(e.ts) <= to)).map((e) => JSON.stringify(e))
      res.setHeader('Content-Type', 'application/x-ndjson')
      res.setHeader('Content-Disposition', 'attachment; filename="pelagos-audit.ndjson"')
      return { raw: `${lines.join('\n')}\n` }
    },

    // Advanced
    'GET /advanced/bind/grammar': () => grammar(),
    'GET /advanced/bind/tree': () => bindTree(state),
    'GET /advanced/kea/{family}/schema': ({ params }) => keaSchema(params.family),
    'GET /advanced/history': ({ query }) => {
      const f = (key, value) => !query.get(key) || value === query.get(key)
      return paginate(state.history.filter((h) => f('engine', h.engine) && f('node_id', h.node_id)), query)
    },
    'GET /advanced/history/{id}': ({ params }) => {
      const item = state.history.find((h) => h.id === params.id)
      if (!item) throw notFound(`history ${params.id}`)
      const stored = state.historyFiles?.[item.id]
      if (stored) {
        const sha256 = Object.fromEntries(Object.keys(stored).map((p) => [p, createHash('sha256').update(stored[p]).digest('hex')]))
        return { manifest: { ...item, sha256 }, files: stored }
      }
      const content = item.engine === 'bind'
        ? '// pelagos:managed\nzone "lab.example.lan" {\n\ttype primary;\n\tfile "db.lab.example.lan";\n};\n'
        : JSON.stringify({ Dhcp4: { 'valid-lifetime': 1800 } }, null, 2)
      return { manifest: { ...item, sha256: { [item.files[0]]: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } }, files: { [item.files[0]]: content } }
    },

    // Install, import, security
    'GET /install/detect': () => ({
      distro: { id: 'debian', like: 'debian', version_id: '13', pretty_name: 'Debian GNU/Linux 13 (trixie)', codename: 'trixie', package_manager: 'apt' },
      engines: {
        bind: { installed: true, binary: '/usr/sbin/named', version: '9.20.11', service: 'named.service', running: true, enabled: true, config: '/etc/bind/named.conf', config_exists: true, source: 'distro', paths: { zone_dir: '/var/cache/bind', rndc_key: '/etc/bind/rndc.key', include_dir: '/etc/bind/pelagos', user: 'bind', group: 'bind' } },
        ...Object.fromEntries([['kea4', 'kea-dhcp4', 'isc-kea-dhcp4-server', 'kea4-ctrl-socket'], ['kea6', 'kea-dhcp6', 'isc-kea-dhcp6-server', 'kea6-ctrl-socket'], ['d2', 'kea-dhcp-ddns', 'isc-kea-dhcp-ddns-server', 'kea-ddns-ctrl-socket']].map(([engine, bin, service, socket]) => [engine, {
          installed: true, binary: `/usr/sbin/${bin}`, version: '3.2.1', service: `${service}.service`, running: true, enabled: true,
          config: `/etc/kea/${bin}.conf`, config_exists: true, source: 'isc',
          paths: { socket: `/run/kea/${socket}`, hooks_dir: '/usr/lib/x86_64-linux-gnu/kea/hooks', lease_dir: '/var/lib/kea', user: '_kea', group: '_kea' },
        }])),
      },
      pelagos: { include_present: true, sockets_ok: true, sockets: {}, keys_present: true, node_initialized: true },
    }),
    'POST /install/plan': ({ body, user }) => {
      const engines = body.engines || []
      if (!engines.length) throw invalid('engines', 'choose at least one engine')
      if (!['distro', 'isc'].includes(body.source)) throw invalid('source', 'must be distro or isc')
      const steps = [
        ...(body.source === 'isc' ? [`add ISC Cloudsmith repository (Kea ${body.isc_series || '3.2'})`] : []),
        ...engines.map((e) => `install ${e} packages`),
        'write minimal configurations with control sockets',
        'create pelagos user and groups',
        'add the Pelagos include lines',
        'enable and start services',
      ]
      return createPlan(state, user, {
        scope: 'install', engine: null, summary: `install ${engines.join(', ')} from ${body.source}`,
        changes: engines.map((e) => ({ op: 'add', target: `install/${e}`, before: null, after: { source: body.source }, node_ids: [] })),
        diff: unifiedDiff('', steps.join('\n'), 'install steps'), targets: [state.selfId], tool: 'apt-get --simulate',
        job: steps,
      })
    },
    'POST /install/import/plan': ({ body, user }) => {
      const engines = body.engines || []
      if (!engines.length) throw invalid('engines', 'choose at least one engine')
      const steps = [
        'read named.conf and Kea configurations',
        'add include "/etc/bind/pelagos/pelagos.conf"; to named.conf',
        'enable statistics-channels on 127.0.0.1:8053',
        'create TSIG keys ddi-read and ddi-admin',
        'propose update-policy for dynamic zones',
        'verify the import',
      ]
      return createPlan(state, user, {
        scope: 'import', engine: null, summary: `import ${engines.join(', ')}`,
        changes: engines.map((e) => ({ op: 'replace', target: `import/${e}`, before: null, after: null, node_ids: [] })),
        diff: unifiedDiff('include "/etc/bind/named.conf.local";', 'include "/etc/bind/named.conf.local";\ninclude "/etc/bind/pelagos/pelagos.conf";', '/etc/bind/named.conf'),
        targets: [state.selfId], tool: 'named-checkconf', job: steps,
      })
    },
    'GET /install/security': ({ query }) => {
      const node = query.get('node')
      const ids = state.nodes.map((n) => n.peer.id).sort((a, b) => (a !== state.selfId) - (b !== state.selfId))
      if (node && node !== 'all' && !ids.includes(node)) throw invalid('node', 'a node id or all')
      const targets = !node ? [state.selfId] : node === 'all' ? ids : [node]
      const name = (id) => state.nodes.find((n) => n.peer.id === id)?.peer.name || id
      return {
        findings: targets.flatMap((id) => markedFindings(state, id)),
        nodes: targets.map((id) => ({ id, name: name(id), ok: true, error: null })),
        node_choices: ids.map((id) => ({ id, name: name(id) })),
        local_node_id: state.selfId,
      }
    },
    'POST /install/security/plan': ({ body, user }) => {
      const selection = body.selection || (body.finding_ids ? { [state.selfId]: body.finding_ids } : {})
      const pairs = Object.entries(selection).flatMap(([nodeId, list]) => (list || []).map((id) => [nodeId, id]))
      if (!pairs.length) throw invalid(body.selection ? 'selection' : 'finding_ids', 'choose at least one finding')
      const byNode = securityByNode(state)
      // Findings the fixtures do not list (a static zone's conversion) are plain remediable ones.
      const lookup = ([nodeId, id]) => (byNode.get(nodeId) || []).find((f) => f.id === id) || { id, remediable: true }
      const manual = pairs.find((p) => lookup(p).remediable === false)
      if (manual) throw invalid('finding_ids', `${manual[1]} has no automatic remediation; follow its proposal by hand`)
      const preconditions = { name: 'security/preconditions', label: 'Check that the configuration did not change', label_message: { key: 'job.step.preconditions', params: {} } }
      const steps = [preconditions, ...pairs.flatMap((p) =>
        isDualKey(lookup(p))
          ? ['add the new key to BIND update-policy', 'switch D2 to the new key on every node', 'remove the old key']
          : [`remediate ${p[1]}`],
      )]
      const nodes = [...new Set(pairs.map(([n]) => n))]
      return createPlan(state, user, {
        scope: 'security', engine: null, summary: `security remediation: ${pairs.length} finding${pairs.length === 1 ? '' : 's'}`,
        summary_message: { key: 'plan.security', params: { count: pairs.length } },
        changes: pairs.map(([nodeId, id]) => ({ op: 'replace', target: `security/${id}`, before: null, after: null, node_ids: [nodeId] })),
        diff: unifiedDiff('key "rndc-key" {\n\talgorithm hmac-md5;\n};', 'key "rndc-key" {\n\talgorithm hmac-sha256;\n};', '/etc/bind/rndc.key'),
        targets: nodes, tool: 'named-checkconf', requires_confirmation: true, job: steps,
        apply: () => {
          // A peer's fixed findings go; this node's stay, as other specs read them.
          for (const [nodeId, id] of pairs) {
            if (nodeId !== state.selfId) byNode.set(nodeId, (byNode.get(nodeId) || []).filter((f) => f.id !== id))
          }
          state.alerts.filter((a) => a.kind === 'insecure_key').forEach((a) => { a.state = 'resolved'; a.resolved_at = iso(Date.now()) })
        },
      })
    },
    // HA listener guard of a node: managed by Pelagos with its HA peer allowed.
    'GET /install/security/ha-guard': ({ query }) => {
      const node = query.get('node') || state.selfId
      if (!state.nodes.some((n) => n.peer.id === node)) throw invalid('node', 'a node id')
      state.haGuards ||= {}
      const peers = state.haGuards[node] || ['192.0.2.12']
      return {
        node_id: node, nft: true, ports: [8001], suggested_peers: ['192.0.2.12'],
        listeners: [{ engine: 'kea4', server: 'ns1', address: '192.0.2.11:8001', port: 8001, peers: ['192.0.2.12'] }],
        managed: { table: 'inet pelagos_kea_ha_guard', unit: 'pelagos-kea-ha-guard.service', file: '/etc/pelagos/kea-ha-guard.nft', peers, ports: [8001], recorded_at: Date.now() / 1000, adopted_from: null, active: true },
        loaded: { peers, ports: [8001] }, legacy: null, differences: [],
      }
    },
    'POST /install/security/ha-guard/plan': ({ body, user }) => {
      const peers = Array.isArray(body.peers) ? body.peers : []
      if (!peers.length || peers.some((p) => !/^[0-9a-f.:/]+$/i.test(p))) throw invalid('peers', 'addresses or prefixes')
      const node = body.node || state.selfId
      state.haGuards ||= {}
      return createPlan(state, user, {
        scope: 'security', engine: null, summary: `HA listener guard: only ${peers.join(', ')} reach TCP 8001`,
        changes: [{ op: 'replace', target: 'security/ha-guard', before: null, after: null, node_ids: [node] }],
        diff: peers.map((p) => `+ ${p}`).join('\n') + '\n', targets: [node], tool: 'nft', requires_confirmation: true,
        job: ['load the guard and watch the peers'],
        apply: () => { state.haGuards[node] = peers },
      })
    },
    'POST /install/security/ha-tls/plan': ({ user }) => createPlan(state, user, {
      scope: 'security', engine: null, summary: 'Kea HA TLS on every peer',
      changes: state.nodes.map((n) => ({ op: 'replace', target: 'security/ha-tls', before: null, after: null, node_ids: [n.peer.id] })),
      diff: '', targets: state.nodes.map((n) => n.peer.id), tool: 'kea', requires_confirmation: true,
      job: ['deposit the certificates', 'switch the standby', 'switch the primary', 'check status-get'],
    }),

    // Administration
    'GET /admin/users': () => ({ items: state.users.map((u) => publicUser(u, state)) }),
    'POST /admin/users': ({ body, user, res }) => {
      if (!body.username || !/^[a-z0-9._-]{2,64}$/.test(body.username)) throw invalid('username', 'lowercase letters, digits, dot, dash and underscore')
      checkPassword('password', body.password)
      if (state.users.some((u) => u.username === body.username)) throw new Problem(409, 'conflict', 'username already exists')
      const roles = body.roles || ['viewer']
      const known = [...state.builtinRoles, ...state.customRoles].map((r) => r.name)
      const unknown = roles.find((r) => !known.includes(r))
      if (unknown) throw invalid('roles', `unknown role ${unknown}`)
      const now = iso(Date.now())
      const created = { id: ulid(), username: body.username, roles, enabled: body.enabled ?? true, has_totp: false, must_change_password: body.must_change_password ?? true, created_at: now, updated_at: now, last_login: null, preferences: {}, password: body.password }
      state.users.push(created)
      auditEntry(state, user, { action: 'user.create', target: `user:${created.username}` })
      res.statusCode = 201
      return publicUser(created, state)
    },
    'GET /admin/users/{id}': ({ params }) => {
      const found = state.users.find((u) => u.id === params.id)
      if (!found) throw notFound(`user ${params.id}`)
      return publicUser(found, state)
    },
    'PUT /admin/users/{id}': ({ params, body, user }) => {
      const found = state.users.find((u) => u.id === params.id)
      if (!found) throw notFound(`user ${params.id}`)
      for (const key of ['roles', 'enabled', 'must_change_password']) if (key in body) found[key] = body[key]
      found.updated_at = iso(Date.now())
      auditEntry(state, user, { action: 'user.update', target: `user:${found.username}` })
      return publicUser(found, state)
    },
    'DELETE /admin/users/{id}': ({ params, user }) => {
      const idx = state.users.findIndex((u) => u.id === params.id)
      if (idx < 0) throw notFound(`user ${params.id}`)
      if (state.users[idx].id === user.id) throw new Problem(409, 'conflict', 'cannot delete yourself')
      const [removed] = state.users.splice(idx, 1)
      auditEntry(state, user, { action: 'user.delete', target: `user:${removed.username}` })
      return null
    },
    'POST /admin/users/{id}/reset-password': ({ params, body }) => {
      const found = state.users.find((u) => u.id === params.id)
      if (!found) throw notFound(`user ${params.id}`)
      checkPassword('password', body.password)
      found.password = body.password
      found.must_change_password = true
      return null
    },
    'DELETE /admin/users/{id}/totp': ({ params }) => {
      const found = state.users.find((u) => u.id === params.id)
      if (!found) throw notFound(`user ${params.id}`)
      found.has_totp = false
      return null
    },
    'GET /admin/roles': () => ({ items: [...state.builtinRoles, ...state.customRoles] }),
    'POST /admin/roles': ({ body, res }) => {
      if (!body.name || !/^[a-z0-9-]{2,64}$/.test(body.name)) throw invalid('name', 'lowercase letters, digits and dashes')
      if ([...state.builtinRoles, ...state.customRoles].some((r) => r.name === body.name)) throw new Problem(409, 'conflict', 'role already exists')
      const bad = (body.permissions || []).find((p) => p !== '*' && !ALL_PERMISSIONS.includes(p))
      if (bad) throw invalid('permissions', `unknown permission ${bad}`)
      const role = { name: body.name, permissions: body.permissions || [], builtin: false, description: body.description || null }
      state.customRoles.push(role)
      res.statusCode = 201
      return role
    },
    'PUT /admin/roles/{name}': ({ params, body }) => {
      if (state.builtinRoles.some((r) => r.name === params.name)) throw new Problem(409, 'conflict', 'built-in roles cannot be changed')
      const role = state.customRoles.find((r) => r.name === params.name)
      if (!role) throw notFound(`role ${params.name}`)
      if ('permissions' in body) role.permissions = body.permissions
      if ('description' in body) role.description = body.description
      return role
    },
    'DELETE /admin/roles/{name}': ({ params }) => {
      if (state.builtinRoles.some((r) => r.name === params.name)) throw new Problem(409, 'conflict', 'built-in roles cannot be deleted')
      const idx = state.customRoles.findIndex((r) => r.name === params.name)
      if (idx < 0) throw notFound(`role ${params.name}`)
      state.customRoles.splice(idx, 1)
      return null
    },
    'GET /admin/permissions': () => ({ items: ALL_PERMISSIONS }),
    'GET /admin/settings': () => state.settings,
    'GET /admin/settings/schema': () => SETTINGS_SCHEMA,
    'PUT /admin/settings': ({ body, user }) => {
      if (!body || typeof body !== 'object' || !Object.keys(body).length) throw invalid('body', 'must be a non-empty object')
      const result = updateSettings(state, body, (errors) => new Problem(400, 'validation_error', 'invalid settings', errors))
      auditEntry(state, user, { action: 'admin.settings.replace', target: 'settings', request: result.body })
      return result.settings
    },
    'GET /admin/modules': () => ({
      cluster: { ...state.modules.cluster },
      nodes: Object.fromEntries(state.nodes.map((n) => [n.peer.id, n.peer.modules])),
    }),
    'PUT /admin/modules': ({ body }) => {
      if (body.cluster) Object.assign(state.modules.cluster, body.cluster)
      for (const [id, mods] of Object.entries(body.nodes || {})) {
        const node = state.nodes.find((n) => n.peer.id === id)
        if (node) Object.assign(node.peer.modules, mods)
      }
      return { cluster: { ...state.modules.cluster }, nodes: Object.fromEntries(state.nodes.map((n) => [n.peer.id, n.peer.modules])) }
    },
    ...opsHandlers(state, { Problem, invalid, hasPermission, auditEntry }),
    ...rpzHandlers(state, { createPlan, invalid, notFound }),
    ...certsHandlers(state, { Problem, invalid }),
    ...notifyHandlers(state, { Problem, invalid }),
    ...archivesHandlers(state, { Problem, invalid, createPlan }),
    ...ddnsFailoverHandlers(state, { Problem, invalid, createPlan, hasPermission }),
    ...resolverHandlers(state, { Problem, invalid, createPlan }),
    ...keaMigrationHandlers(state, { Problem, invalid }),
    ...ipv6Handlers(state, { Problem, invalid }),
  }
}

// ------------------------------------------------------------------ server

function parseCookies(header) {
  const out = {}
  for (const part of (header || '').split(';')) {
    const [k, ...v] = part.trim().split('=')
    if (k) out[k] = v.join('=')
  }
  return out
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

// `live` paces the mock like a cluster: plans take time per node, secondaries transfer after
// a change, HA servers report a heartbeat every haBeatMs. Off by default for unit tests.
export function createMockServer({ quiet = false, jobStepMs, live = false, applyNodeMs = live ? 350 : 0, transferMs = live ? 1500 : 0, haBeatMs = live ? 3000 : 0, scenario = 'pair' } = {}) {
  const state = createState(scenario)
  state.ptr = ptrHelpers(state, { reverseToIp, v6Nibbles, canonicalV6 })
  if (jobStepMs !== undefined) state.jobStepMs = jobStepMs
  state.applyNodeMs = applyNodeMs
  state.transferMs = transferMs

  const sessionOf = (req) => {
    const sid = parseCookies(req.headers.cookie).pelagos_session
    const session = sid && state.sessions.get(sid)
    if (!session) return { sid: null, session: null, user: null }
    const record = state.users.find((u) => u.id === session.userId)
    if (!record || !record.enabled) return { sid: null, session: null, user: null }
    return { sid, session, user: { ...record, permissions: permissionsOf(state, record) } }
  }

  const hub = createWsHub({ authenticate: (req) => sessionOf(req).user, nodeId: state.selfId })
  state.emit = hub.emit
  const handlers = buildHandlers(state, hub.emit)
  const events = createEvents(state, {
    emit: hub.emit, inPool4, poolRange, ipToInt, utilization, bumpSerial, findZone, liveHa,
  })
  const missing = ENDPOINTS.filter((spec) => !handlers[spec])
  if (missing.length) throw new Error(`mock server misses handlers for: ${missing.join(', ')}`)

  const sendJson = (res, status, body, type = 'application/json') => {
    if (status === 204 || body === null || body === undefined) {
      res.statusCode = status === 200 ? 204 : status
      res.end()
      return
    }
    res.statusCode = status
    if (!res.getHeader('Content-Type')) res.setHeader('Content-Type', type)
    res.end(JSON.stringify(body))
  }

  const sendProblem = (res, req, problem) => {
    const body = {
      type: `urn:pelagos:error:${problem.code}`,
      title: TITLES[problem.code] || problem.code,
      status: problem.status,
      detail: problem.message,
      instance: req.url.split('?')[0],
      code: problem.code,
      ...(problem.errors ? { errors: problem.errors } : {}),
      ...(problem.extra || {}),
    }
    res.statusCode = problem.status
    res.setHeader('Content-Type', 'application/problem+json')
    res.end(JSON.stringify(body))
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://mock')
    const started = Date.now()
    res.on('finish', () => {
      if (!quiet) console.log(`${req.method} ${url.pathname}${url.search} ${res.statusCode} ${Date.now() - started}ms`)
    })
    try {
      // Mock only: produce a cluster event (see events.mjs).
      if (url.pathname === `${API}/_mock/events` && req.method === 'POST') {
        const raw = await readBody(req)
        const body = raw ? JSON.parse(raw) : {}
        const out = events.run(body.kind, body)
        if (!out) throw new Problem(404, 'not_found', `unknown event kind ${body.kind}`)
        sendJson(res, 200, out)
        return
      }
      // Mock only: switch the cluster to another scenario (pair, three, four); sessions stay.
      if (url.pathname === `${API}/_mock/scenario` && req.method === 'POST') {
        const raw = await readBody(req)
        const name = (raw ? JSON.parse(raw) : {}).name
        if (!SCENARIOS[name]) throw new Problem(404, 'not_found', `unknown scenario ${name}`)
        const keep = { sessions: state.sessions, emit: state.emit, jobStepMs: state.jobStepMs, applyNodeMs: state.applyNodeMs, transferMs: state.transferMs, ptr: state.ptr }
        for (const k of Object.keys(state)) delete state[k]
        Object.assign(state, createState(name), keep)
        hub.emit('nodes', 'status', state.nodes.find((n) => !n.is_self) || state.nodes[0])
        sendJson(res, 200, { scenario: name, nodes: state.nodes.map((n) => n.peer.name) })
        return
      }
      if (!url.pathname.startsWith(`${API}/`)) throw new Problem(404, 'not_found', 'not an API path')
      const path = url.pathname.slice(API.length)
      const route = routeOf(req.method, path)
      if (!route) {
        const otherMethod = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].some((m) => m !== req.method && routeOf(m, path))
        throw otherMethod ? new Problem(405, 'method_not_allowed', `${req.method} not allowed`) : new Problem(404, 'not_found', `no route for ${path}`)
      }
      const raw = await readBody(req)
      let body = {}
      // A multipart upload (archives) is not JSON: handlers read its headers only.
      if (raw && !String(req.headers['content-type'] || '').startsWith('multipart/form-data')) {
        try {
          body = JSON.parse(raw)
        } catch {
          throw new Problem(400, 'validation_error', 'body is not valid JSON')
        }
      }
      const { sid, session, user } = sessionOf(req)
      if (!ANON.has(route.spec)) {
        if (!user) throw new Problem(401, 'unauthenticated', 'Authentication required')
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.headers['x-csrf-token'] !== session.csrf) {
          throw new Problem(403, 'csrf_failed', 'Missing or wrong X-CSRF-Token')
        }
        const permission = PERMISSIONS[route.spec]
        if (permission && !hasPermission(user, permission)) throw new Problem(403, 'forbidden', `requires ${permission}`)
        if (route.params.family === 'v6' && !state.modules.cluster.dhcpv6) throw new Problem(404, 'module_disabled', 'the DHCPv6 module is disabled')
        if (route.spec.startsWith('GET /dashboard/summary') && !['read:dns', 'read:dhcp', 'read:nodes'].some((p) => hasPermission(user, p))) {
          throw new Problem(403, 'forbidden', 'requires any read permission')
        }
      }
      const result = await handlers[route.spec]({ req, res, params: route.params, query: url.searchParams, body, user, session, sid })
      if (result && typeof result === 'object' && 'raw' in result && Object.keys(result).length === 1) {
        res.statusCode = 200
        res.end(result.raw)
        return
      }
      sendJson(res, res.statusCode && res.statusCode !== 200 ? res.statusCode : 200, result)
    } catch (err) {
      if (err instanceof Problem) sendProblem(res, req, err)
      else {
        if (!quiet) console.error(err)
        sendProblem(res, req, new Problem(500, 'internal_error', err.message))
      }
    }
  })

  server.on('upgrade', (req, socket) => {
    if (new URL(req.url, 'http://mock').pathname !== `${API}/ws`) {
      socket.destroy()
      return
    }
    hub.handleUpgrade(req, socket)
  })

  // Lease summaries and node heartbeats keep the WebSocket indicator alive.
  const ticker = setInterval(() => {
    hub.emit('leases', 'summary', { engine: 'kea4', active: leasesFor(state, 'v4').length, new_since_last: 2, expired_since_last: 1 })
    // Peers only, like the collector (this node is not one of its peers).
    for (const node of state.nodes) {
      node.last_seen = iso(Date.now())
      if (!node.is_self) hub.emit('nodes', 'status', node)
    }
  }, 15000)
  ticker.unref?.()
  const beat = haBeatMs > 0 ? setInterval(() => events.run('heartbeat'), haBeatMs) : null
  beat?.unref?.()

  return {
    state,
    server,
    hub,
    listen(port = 8481, host = '127.0.0.1') {
      return new Promise((resolve) => {
        server.listen(port, host, () => resolve(server.address()))
      })
    },
    events,
    close() {
      clearInterval(ticker)
      if (beat) clearInterval(beat)
      stopEventTimers()
      hub.closeAll()
      return new Promise((resolve) => server.close(() => resolve()))
    },
  }
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]
if (isMain) {
  const args = process.argv.slice(2)
  const portArg = args.indexOf('--port')
  const port = Number(portArg >= 0 ? args[portArg + 1] : process.env.MOCK_PORT || 8481)
  const host = process.env.MOCK_HOST || '127.0.0.1'
  const scenarioArg = args.indexOf('--scenario')
  const scenario = scenarioArg >= 0 ? args[scenarioArg + 1] : process.env.MOCK_SCENARIO || 'pair'
  const mock = createMockServer({ quiet: args.includes('--quiet'), live: !args.includes('--static'), scenario })
  mock.listen(port, host).then((addr) => {
    console.log(`Pelagos mock API on http://${addr.address}:${addr.port}${API} (users: admin/admin, alice/alice, bob/bob + 123456, viewer/viewer)`)
  })
  const stop = () => mock.close().then(() => process.exit(0))
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}
