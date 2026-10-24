// SPDX-License-Identifier: Apache-2.0
// Mock Pelagos API: every endpoint of docs/architecture.md section 17 plus the
// WebSocket of section 18, in memory, with sessions, CSRF, RBAC, RFC 7807
// errors, pagination and the plan lifecycle. `npm run mock` starts it on
// 127.0.0.1:8481 (or --port N); Vite proxies /api to it when VITE_API_MOCK=1.
// Users: admin/admin, alice/alice (dns-operator), bob/bob + TOTP 123456
// (dhcp-operator), viewer/viewer.
import http from 'node:http'
import { randomBytes } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { ENDPOINTS } from '../src/services/endpoints.js'
import { createState, iso, ulid, ALL_PERMISSIONS } from './data.mjs'
import { createPlan, applyPlan, rollbackPlan, unifiedDiff, jsonText, rrsetText, isExpired, auditEntry } from './plans.mjs'
import { createWsHub } from './ws.mjs'

const API = '/api/v1'
const ANON = new Set(['GET /health', 'GET /version', 'POST /auth/login'])

// Permission of each endpoint (section 17); undefined means any authenticated user.
const PERMISSIONS = {
  'GET /nodes': 'read:nodes', 'GET /nodes/self': 'read:nodes', 'GET /nodes/{id}': 'read:nodes',
  'POST /nodes/enroll-token': 'admin:nodes', 'DELETE /nodes/{id}': 'admin:nodes', 'POST /nodes/{id}/sync': 'admin:nodes',
  'GET /nodes/replication': 'read:nodes',
  'GET /dns/instances': 'read:dns', 'GET /dns/zones': 'read:dns', 'GET /dns/zones/{zone}': 'read:dns',
  'POST /dns/zones/plan': 'write:dns.zones', 'GET /dns/zones/{zone}/records': 'read:dns',
  'POST /dns/zones/{zone}/records/plan': 'write:dns.records', 'POST /dns/zones/{zone}/retransfer': 'ops:dns',
  'POST /dns/zones/{zone}/notify': 'ops:dns', 'POST /dns/zones/{zone}/reload': 'ops:dns',
  'GET /dns/zones/{zone}/dnssec': 'read:dns', 'GET /dns/config': 'read:dns', 'POST /dns/config/plan': 'write:dns.config',
  'GET /dns/keys': 'read:dns', 'GET /dns/keys/{name}/secret': 'read:dns.secrets', 'POST /dns/keys/plan': 'write:dns.config',
  'GET /dns/acls': 'read:dns', 'POST /dns/acls/plan': 'write:dns.config', 'GET /dns/resolver': 'read:dns',
  'POST /dns/resolver/plan': 'write:dns.config', 'GET /dns/rpz': 'read:dns', 'GET /dns/catalog-zones': 'read:dns',
  'GET /dns/stats': 'read:dns',
  'POST /dhcp/{family}/subnets/plan': 'write:dhcp.subnets', 'POST /dhcp/{family}/shared-networks/plan': 'write:dhcp.subnets',
  'POST /dhcp/{family}/client-classes/plan': 'write:dhcp.classes', 'POST /dhcp/{family}/options/plan': 'write:dhcp.options',
  'POST /dhcp/{family}/reservations/plan': 'write:dhcp.reservations', 'POST /dhcp/{family}/leases/{ip}/delete/plan': 'ops:dhcp.leases',
  'POST /dhcp/{family}/ha/maintenance/plan': 'ops:dhcp.ha', 'POST /dhcp/{family}/service/plan': 'ops:dhcp.ha',
  'POST /dhcp/{family}/ddns/plan': 'write:dhcp.options', 'POST /dhcp/{family}/hooks/plan': 'write:dhcp.config',
  'POST /dhcp/{family}/config/plan': 'write:dhcp.config', 'POST /dhcp/d2/config/plan': 'write:dhcp.config',
  'GET /hosts': 'read:hosts', 'GET /hosts/{key}': 'read:hosts', 'POST /hosts/plan': 'write:hosts',
  'GET /alerts': 'read:alerts', 'GET /alerts/summary': 'read:alerts', 'POST /alerts/{id}/ack': 'write:alerts',
  'POST /alerts/consistency/run': 'write:alerts',
  'GET /series/pools': 'read:series', 'GET /series/serials': 'read:series', 'GET /series/ha-transitions': 'read:series',
  'GET /audit': 'read:audit', 'GET /audit/{id}': 'read:audit', 'GET /audit/export': 'read:audit',
  'GET /advanced/bind/grammar': 'read:advanced', 'GET /advanced/bind/tree': 'read:advanced',
  'GET /advanced/kea/{family}/schema': 'read:advanced', 'GET /advanced/history': 'read:advanced',
  'GET /advanced/history/{id}': 'read:advanced',
  'GET /install/detect': 'admin:install', 'POST /install/plan': 'admin:install', 'POST /install/import/plan': 'admin:install',
  'GET /install/security': 'admin:install', 'POST /install/security/plan': 'admin:install',
  'GET /admin/users': 'admin:users', 'POST /admin/users': 'admin:users', 'GET /admin/users/{id}': 'admin:users',
  'PUT /admin/users/{id}': 'admin:users', 'DELETE /admin/users/{id}': 'admin:users',
  'POST /admin/users/{id}/reset-password': 'admin:users', 'DELETE /admin/users/{id}/totp': 'admin:users',
  'GET /admin/roles': 'admin:roles', 'POST /admin/roles': 'admin:roles', 'PUT /admin/roles/{name}': 'admin:roles',
  'DELETE /admin/roles/{name}': 'admin:roles', 'GET /admin/permissions': 'admin:roles',
  'GET /admin/settings': 'admin:settings', 'PUT /admin/settings': 'admin:settings',
  'GET /admin/modules': 'admin:modules', 'PUT /admin/modules': 'admin:modules',
}
for (const spec of ENDPOINTS) {
  if (spec.includes(' /dhcp/') && spec.startsWith('GET ') && !PERMISSIONS[spec]) PERMISSIONS[spec] = 'read:dhcp'
}

class Problem extends Error {
  constructor(status, code, detail, errors) {
    super(detail)
    this.status = status
    this.code = code
    this.errors = errors
  }
}
const notFound = (what) => new Problem(404, 'not_found', `${what} not found`)
const invalid = (field, message) => new Problem(400, 'validation_error', 'Invalid request', [{ field, message }])

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
        params[name] = decodeURIComponent(segments[i])
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

function zoneSerials(state, zone) {
  const serial = state.soaSerial(state.records[zone.name])
  const serials = {}
  for (const node of state.nodes) {
    let value = serial
    if (zone.name === 'lab.example.lan.' && !node.is_self) value = serial - 1
    if (zone.kind === 'forward') value = null
    serials[node.peer.id] = value
  }
  const values = Object.values(serials).filter((v) => v !== null)
  return { serials, divergent: new Set(values).size > 1 }
}

function zoneStatus(state, zone, nodeId) {
  const { serials } = zoneSerials(state, zone)
  return {
    zone: zone.name,
    view: zone.view,
    node_id: nodeId,
    kind: zone.kind,
    serial: serials[nodeId],
    config_serial: serials[nodeId],
    dynamic: zone.dynamic,
    signed: Boolean(zone.dnssec_policy),
    files: zone.file ? [zone.file] : [],
    next_refresh: zone.kind === 'secondary' ? iso(Date.now() + 3200000) : null,
    expires: zone.kind === 'secondary' ? iso(Date.now() + 1209600000) : null,
    last_loaded: iso(Date.now() - 3600000),
    raw: { type: zone.kind, 'files': zone.file || '', 'dynamic': zone.dynamic ? 'yes' : 'no' },
    error: null,
    collected_at: iso(Date.now() - 15000),
  }
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
      items.push({ subnet_id: subnet.id, subnet: subnet.subnet, pool: p.pool, total, assigned, declined, percent: Math.round((assigned / total) * 1000) / 10 })
    }
  }
  return items
}

function subnetUtilization(state, family) {
  const out = {}
  for (const row of utilization(state, family)) {
    const cur = out[row.subnet_id] || { total: 0, assigned: 0, percent: 0 }
    cur.total += row.total
    cur.assigned += row.assigned
    cur.percent = Math.round((cur.assigned / cur.total) * 1000) / 10
    out[row.subnet_id] = cur
  }
  return out
}

function buildHosts(state) {
  const hosts = new Map()
  const leases = leasesFor(state, 'v4')
  const records = state.records['example.lan.'] || []
  const reverse = state.records['2.0.192.in-addr.arpa.'] || []
  const add = (key, patch) => {
    const host = hosts.get(key) || { key, mac: null, ips: [], hostname: null, lease: null, reservation: null, records: [], alerts: [] }
    hosts.set(key, Object.assign(host, patch(host)))
  }
  for (const lease of leases) {
    const key = lease.hw_address ? `mac:${lease.hw_address}` : `ip:${lease.ip_address}`
    add(key, (h) => ({ mac: lease.hw_address, ips: [...new Set([...h.ips, lease.ip_address])], hostname: absName(lease.hostname?.includes('.') ? lease.hostname : `${lease.hostname}.example.lan`), lease }))
  }
  for (const r of state.reservations.v4) {
    const key = `mac:${r.identifier}`
    add(key, (h) => ({ mac: r.identifier, ips: [...new Set([...h.ips, r.ip_address])], hostname: h.hostname || absName(r.hostname), reservation: r }))
  }
  for (const rrset of records.filter((r) => r.rtype === 'A')) {
    for (const ip of rrset.rdata) {
      const existing = [...hosts.values()].find((h) => h.ips.includes(ip))
      const key = existing ? existing.key : `ip:${ip}`
      add(key, (h) => ({ ips: [...new Set([...h.ips, ip])], hostname: h.hostname || rrset.name, records: [...h.records, rrset] }))
    }
  }
  for (const host of hosts.values()) {
    for (const ip of host.ips) {
      const last = ip.split('.')[3]
      const ptr = reverse.find((r) => r.name === `${last}.2.0.192.in-addr.arpa.`)
      if (ptr && !host.records.includes(ptr)) host.records.push(ptr)
      host.alerts.push(...state.alerts.filter((a) => a.subject === `ip:${ip}` && a.state !== 'resolved'))
    }
  }
  return [...hosts.values()].sort((a, b) => ipToInt(a.ips[0] || '0.0.0.0') - ipToInt(b.ips[0] || '0.0.0.0'))
}

function summary(state) {
  const pools = []
  for (const family of ['v4', 'v6']) {
    for (const row of utilization(state, family)) {
      pools.push({ node_id: state.selfId, engine: family === 'v4' ? 'kea4' : 'kea6', subnet_id: row.subnet_id, subnet: row.subnet, pool: row.pool, total: row.total, assigned: row.assigned, percent: row.percent })
    }
  }
  const open = state.alerts.filter((a) => a.state === 'open')
  return {
    nodes: state.nodes,
    ha: [...state.ha.v4, ...state.ha.v6],
    pools,
    zones: state.zones.filter((z) => z.kind !== 'forward').map((z) => ({ zone: z.name, view: z.view, ...zoneSerials(state, z) })),
    d2: Object.values(state.d2),
    alerts: {
      open: open.length,
      critical: open.filter((a) => a.severity === 'critical').length,
      warning: open.filter((a) => a.severity === 'warning').length,
      info: open.filter((a) => a.severity === 'info').length,
    },
    engines: capabilities(state).engines,
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
    collected_at: iso(Date.now() - 20000),
    version: state.dnsCapabilities.version,
    boot_time: iso(Date.now() - 86400000 * 6),
    config_time: iso(Date.now() - 3600000),
    opcodes: { QUERY: 184233, NOTIFY: 52, UPDATE: 2840 },
    rcodes: { NOERROR: 170020, NXDOMAIN: 13110, SERVFAIL: 12, REFUSED: 91 },
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

function bindConfig(state) {
  return {
    includes: ['/etc/bind/named.conf', '/etc/bind/named.conf.options', '/etc/bind/named.conf.local', '/etc/bind/pelagos/pelagos.conf', '/etc/bind/pelagos/keys.conf', '/etc/bind/pelagos/acls.conf', '/etc/bind/pelagos/zones.conf', '/etc/bind/pelagos/options.conf'],
    options: {
      directory: '"/var/cache/bind"',
      recursion: state.resolver.recursion ? 'yes' : 'no',
      'allow-recursion': `{ ${state.resolver.allow_recursion.join('; ')}; }`,
      forwarders: `{ ${state.resolver.forwarders.join('; ')}; }`,
      forward: state.resolver.forward,
      'dnssec-validation': state.resolver.dnssec_validation,
    },
    keys: Object.fromEntries(state.keys.map((k) => [k.name, { algorithm: k.algorithm, secret: '********', provenance: { file: k.config_path, line: 1 } }])),
    acls: Object.fromEntries(state.acls.map((a) => [a.name, { elements: a.elements, provenance: { file: a.config_path, line: 1 } }])),
    controls: [{ inet: '127.0.0.1', port: 953, allow: ['127.0.0.1'], keys: ['rndc-key'] }],
    statistics_channels: [{ inet: '127.0.0.1', port: 8053, allow: ['127.0.0.1'] }],
    logging: 'channel default_log { file "/var/log/named/default.log" versions 3 size 20m; severity info; };',
    views: {},
    zones: state.zones,
    pelagos: {
      managed_files: ['keys.conf', 'acls.conf', 'zones.conf', 'options.conf'],
      include_present: true,
      options_include_present: true,
    },
  }
}

function keaSchema(family) {
  const root = family === 'v4' ? 'Dhcp4' : 'Dhcp6'
  const k = (name, type, description, extra = {}) => ({ name, type, description, ...extra })
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
        const points = []
        for (let t = from, i = 0; t <= to && i < 2000; t += step, i += 1) {
          const wave = Math.sin((t / 3600000 / 24) * Math.PI * 2 + idx) * 0.15
          const assigned = Math.max(0, Math.min(r.total, Math.round(r.assigned * (0.85 + wave))))
          points.push([iso(t), assigned, r.total])
        }
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
  const oldText = normalized.map((c) => rrsetText(c.before)).filter(Boolean).join('\n')
  const newText = normalized.map((c) => rrsetText(c.after)).filter(Boolean).join('\n')
  const serial = state.soaSerial(records)
  const bad = normalized.some((c) => c.after?.rdata.some((r) => /invalid/i.test(r)))
  const snapshot = JSON.parse(JSON.stringify(records))
  return createPlan(state, user, {
    scope: 'dns.rrset',
    engine: 'bind',
    summary: `${normalized.length} change(s) in ${zone.name}`,
    changes: normalized,
    diff: unifiedDiff(oldText, newText, zone.name),
    targets: [state.selfId],
    tool: 'dnspython',
    preconditions: [
      { kind: 'soa_serial', node_id: state.selfId, subject: zone.name, value: String(serial) },
      ...normalized.map((c) => ({ kind: c.before ? 'rrset_exists' : 'rrset_absent', node_id: state.selfId, subject: c.target, value: c.before ? c.before.rdata.join(' ') : '' })),
    ],
    validations: [{ ok: !bad, tool: 'dnspython', output: bad ? 'rdata does not parse' : '', node_id: state.selfId }],
    apply() {
      for (const c of normalized) {
        const idx = records.findIndex((r) => r.name === c.before?.name && r.rtype === c.before?.rtype)
        if (c.before && idx >= 0) records.splice(idx, 1)
        if (c.after) records.push(c.after)
      }
      bumpSerial(records)
      return 'NOERROR'
    },
    rollback() {
      records.splice(0, records.length, ...snapshot)
      bumpSerial(records)
    },
  })
}

function bumpSerial(records) {
  const soa = records.find((r) => r.rtype === 'SOA')
  if (!soa) return
  const parts = soa.rdata[0].split(/\s+/)
  parts[2] = String(Number(parts[2]) + 1)
  soa.rdata[0] = parts.join(' ')
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
    preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: engine || scope, value: 'a1b2c3d4e5f6' })),
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
    preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: engine || scope, value: 'a1b2c3d4e5f6' })),
    apply: () => apply(next),
    rollback: () => apply(before),
  })
}

// ------------------------------------------------------------------ handlers

function buildHandlers(state, emit) {
  const kea = (family) => (family === 'v4' ? 'kea4' : 'kea6')
  const keaTool = (family) => `kea-dhcp${family === 'v4' ? '4' : '6'} -t`
  const nodeOr = (q) => q.get('node_id') || state.selfId

  return {
    // Meta
    'GET /health': () => ({ status: 'ok', replication: 'ready', node_id: state.selfId, time: iso(Date.now()) }),
    'GET /version': () => ({ version: '0.1.0', api: 'v1', python: '3.12.11', build: 'mock' }),
    'GET /capabilities': () => capabilities(state),

    // Auth and account
    'POST /auth/login': ({ body, res }) => {
      const user = state.users.find((u) => u.username === body.username)
      if (!user || user.password !== body.password || !user.enabled) {
        auditEntry(state, null, { action: 'auth.login', target: `user:${body.username}`, result: 'denied', message: 'invalid credentials' })
        throw new Problem(401, 'invalid_credentials', 'Invalid username or password')
      }
      if (user.has_totp) {
        if (!body.totp_code) throw new Problem(401, 'totp_required', 'A TOTP code is required')
        if (body.totp_code !== (user.totp || '123456')) throw new Problem(401, 'invalid_credentials', 'Invalid TOTP code')
      }
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
      if (!body.new_password || body.new_password.length < 8) throw invalid('new_password', 'must be at least 8 characters')
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
      theme_family: 'pelagic',
      theme_mode: 'system',
      language: 'en',
      dashboard_layout: null,
      ...(state.preferences.get(user.id) || {}),
    }),
    'PUT /account/preferences': ({ user, body }) => {
      const allowed = ['theme_family', 'theme_mode', 'language', 'dashboard_layout']
      const merged = { ...(state.preferences.get(user.id) || {}) }
      for (const key of allowed) if (key in body) merged[key] = body[key]
      state.preferences.set(user.id, merged)
      return { theme_family: 'pelagic', theme_mode: 'system', language: 'en', dashboard_layout: null, ...merged }
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
        command: `pelagos enroll --url https://ns1.example.lan:8444 --token ${token} --ca-fingerprint sha256:4f2a9c...`,
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
          .map((z) => ({ zone: z, ...zoneSerials(state, z) })),
      }
    },
    'GET /dns/zones/{zone}': ({ params, query }) => {
      const zone = findZone(state, params.zone, query.get('view'))
      return { zone, status: Object.fromEntries(state.nodes.map((n) => [n.peer.id, zoneStatus(state, zone, n.peer.id)])) }
    },
    'POST /dns/zones/plan': ({ body, user }) => {
      const change = body.change
      const [view = '_default', name] = String(change?.target || '').split('/')
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
              ],
              ds: ['48217 13 2 4C3F2A8E9D0B1C7F6A5E4D3C2B1A0F9E8D7C6B5A4F3E2D1C0B9A8F7E6D5C4B3A'],
              next_resign: iso(Date.now() + 3600000 * 5),
            }
          : { signed: false, policy: null, keys: [] },
      }
    },
    'GET /dns/config': () => bindConfig(state),
    'POST /dns/config/plan': ({ body, user }) => {
      if (!Array.isArray(body.changes) || !body.changes.length) throw invalid('changes', 'at least one change is required')
      const first = body.changes[0]
      const statement = String(first.target || '').replace(/^options\//, '')
      const current = bindConfig(state).options[statement] ?? null
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
      const keys = ['recursion', 'allow_recursion', 'forwarders', 'forward', 'dnssec_validation']
      const next = { ...state.resolver }
      for (const key of keys) if (key in body) next[key] = body[key]
      return settingsPlan(state, user, {
        scope: 'dns.config', engine: 'bind', target: 'options/resolver', current: state.resolver, next,
        tool: 'named-checkconf', summary: 'update resolver settings',
        apply: (value) => Object.assign(state.resolver, value),
      })
    },
    'GET /dns/rpz': () => ({
      items: [
        { zone: 'rpz.example.lan.', policy: 'given', source: 'user_conf' },
        { zone: 'feed.rpz.example.', policy: 'nxdomain', source: 'user_conf' },
      ],
    }),
    'GET /dns/catalog-zones': () => ({
      items: [{ zone: 'catalog.example.lan.', default_primaries: ['192.0.2.53'], member_count: 4, source: 'user_conf' }],
    }),
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
    'GET /dhcp/{family}/leases': ({ params, query }) => {
      const q = (query.get('q') || '').toLowerCase()
      const subnetId = query.get('subnet_id')
      const stateFilter = query.get('state')
      const items = leasesFor(state, params.family, query.get('node_id'))
        .filter((l) => !subnetId || String(l.subnet_id) === subnetId)
        .filter((l) => !stateFilter || l.state === stateFilter)
        .filter((l) => !q || [l.ip_address, l.hw_address, l.hostname, l.client_id, l.duid].some((v) => v && v.toLowerCase().includes(q)))
      return paginate(items, query, { node_id: query.get('node_id') || state.selfId })
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
      const statistics = { 'pkt4-received': 120220, 'pkt4-discover-received': 30110, 'pkt4-request-received': 70210, 'pkt4-ack-sent': 70011, 'pkt4-nak-sent': 12, 'pkt4-receive-drop': 3 }
      items.forEach((r, i) => {
        statistics[`subnet[${r.subnet_id}].pool[${i}].total-addresses`] = r.total
        statistics[`subnet[${r.subnet_id}].pool[${i}].assigned-addresses`] = r.assigned
        statistics[`subnet[${r.subnet_id}].pool[${i}].declined-addresses`] = r.declined
      })
      return { node_id: nodeOr(query), statistics }
    },
    'GET /dhcp/{family}/ha': ({ params }) => ({ items: state.ha[params.family] }),
    'POST /dhcp/{family}/ha/maintenance/plan': ({ params, body, user }) => {
      if (!['start', 'cancel'].includes(body.action)) throw invalid('action', 'must be start or cancel')
      const ha = state.ha[params.family]
      const target = ha.find((h) => h.node_id === body.node_id)
      if (!target) throw notFound(`HA server on node ${body.node_id}`)
      const partner = ha.find((h) => h !== target)
      const before = ha.map((h) => ({ node_id: h.node_id, state: h.state }))
      return createPlan(state, user, {
        scope: 'dhcp.ha',
        engine: kea(params.family),
        summary: `${body.action === 'start' ? 'start' : 'cancel'} HA maintenance on ${nodeName(state, body.node_id)}`,
        changes: [{ op: 'replace', target: `ha/${nodeName(state, body.node_id)}`, before: target.state, after: body.action === 'start' ? 'in-maintenance' : 'hot-standby', node_ids: [body.node_id] }],
        diff: unifiedDiff(`state: ${target.state}`, `state: ${body.action === 'start' ? 'in-maintenance' : 'hot-standby'}`, `ha ${nodeName(state, body.node_id)}`),
        targets: [body.node_id],
        tool: 'ha-maintenance-start',
        requires_confirmation: true,
        preconditions: [{ kind: 'ha_state', node_id: body.node_id, subject: 'ha', value: target.state }],
        apply() {
          if (body.action === 'start') {
            target.state = 'in-maintenance'
            if (partner) partner.state = 'partner-in-maintenance'
          } else {
            target.state = 'hot-standby'
            if (partner) partner.state = 'hot-standby'
          }
          ha.forEach((h) => emit('ha', 'state', h))
        },
        rollback() {
          for (const b of before) ha.find((h) => h.node_id === b.node_id).state = b.state
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
      config: keaConfig(state, params.family),
    }),
    'POST /dhcp/{family}/config/plan': ({ params, body, user }) => {
      if (!body.config || typeof body.config !== 'object') throw invalid('config', 'required')
      const current = keaConfig(state, params.family)
      const root = params.family === 'v4' ? 'Dhcp4' : 'Dhcp6'
      const ok = Boolean(body.config[root])
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
        preconditions: state.nodes.map((n) => ({ kind: 'config_hash', node_id: n.peer.id, subject: kea(params.family), value: 'a1b2c3d4e5f6' })),
        apply: () => 'config-set and config-write done',
        rollback: () => {},
      })
      return plan
    },
    'GET /dhcp/d2/servers': () => ({
      items: state.nodes.map((n) => ({ node_id: n.peer.id, capabilities: capabilities(state).engines.d2, status: { pid: 1300, uptime: 512000 } })),
    }),
    'GET /dhcp/d2/stats': ({ query }) => state.d2[nodeOr(query)] || (() => { throw notFound('D2 on this node') })(),
    'GET /dhcp/d2/config': ({ query }) => ({ node_id: nodeOr(query), config: d2Config() }),
    'POST /dhcp/d2/config/plan': ({ body, user }) => {
      if (!body.config || typeof body.config !== 'object') throw invalid('config', 'required')
      return createPlan(state, user, {
        scope: 'd2.config',
        engine: 'd2',
        summary: 'replace the D2 configuration',
        changes: [{ op: 'replace', target: 'config', before: d2Config(), after: body.config, node_ids: body.node_ids || [] }],
        diff: unifiedDiff(jsonText(d2Config()), jsonText(body.config), 'kea-dhcp-ddns.conf'),
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
      if (!body.hostname) errors.push({ field: 'hostname', message: 'required' })
      if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(body.ip || '')) errors.push({ field: 'ip', message: 'must be an IPv4 address' })
      if (body.reservation && !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(body.mac || '')) errors.push({ field: 'mac', message: 'required for a reservation, lowercase colon-separated' })
      if (errors.length) throw new Problem(400, 'validation_error', 'Invalid host', errors)
      const zone = absName(body.zone || 'example.lan')
      const fqdn = absName(body.hostname.includes('.') ? body.hostname : `${body.hostname}.${zone}`)
      const ttl = Number(body.ttl || 3600)
      const records = state.records[zone]
      if (!records) throw notFound(`zone ${zone}`)
      const reverseZone = absName(body.reverse_zone || '2.0.192.in-addr.arpa')
      const ptrName = `${body.ip.split('.')[3]}.${reverseZone}`
      const reverse = state.records[reverseZone] || null
      const reservation = body.reservation
        ? {
            subnet_id: body.subnet_id ?? 1,
            id_type: 'hw-address',
            identifier: body.mac.toLowerCase(),
            ip_address: body.ip,
            ip_addresses: [],
            prefixes: [],
            hostname: fqdn.replace(/\.$/, ''),
            client_classes: [],
            options: [],
            next_server: null,
            server_hostname: null,
            boot_file_name: null,
            user_context: body.notes ? { 'pelagos:note': body.notes } : {},
            raw: {},
          }
        : null
      const changes = [
        { op: 'add', target: `${zone}/${fqdn}/A`, before: null, after: { name: fqdn, rtype: 'A', ttl, rdata: [body.ip] }, node_ids: [] },
        ...(reverse ? [{ op: 'add', target: `${reverseZone}/${ptrName}/PTR`, before: null, after: { name: ptrName, rtype: 'PTR', ttl, rdata: [fqdn] }, node_ids: [] }] : []),
        ...(reservation ? [{ op: 'add', target: `subnet4/${reservation.subnet_id}/reservations/hw-address=${reservation.identifier}`, before: null, after: reservation, node_ids: [] }] : []),
      ]
      const text = changes.map((c) => (c.after.rtype ? rrsetText(c.after) : jsonText(c.after))).join('\n')
      return createPlan(state, user, {
        scope: 'host',
        engine: null,
        summary: `create host ${fqdn} (${body.ip})`,
        changes,
        diff: unifiedDiff('', text, `host ${fqdn}`),
        targets: state.nodes.map((n) => n.peer.id),
        validations: [
          { ok: true, tool: 'dnspython', output: '', node_id: state.selfId },
          ...(reservation ? [{ ok: true, tool: 'kea-dhcp4 -t', output: '', node_id: state.selfId }] : []),
        ],
        preconditions: [{ kind: 'rrset_absent', node_id: state.selfId, subject: `${zone}/${fqdn}/A`, value: '' }],
        apply() {
          records.push(changes[0].after)
          bumpSerial(records)
          if (reverse) {
            reverse.push(changes[1].after)
            bumpSerial(reverse)
          }
          if (reservation) state.reservations.v4.push(reservation)
        },
        rollback() {
          records.splice(records.indexOf(changes[0].after), 1)
          if (reverse) reverse.splice(reverse.indexOf(changes[1].after), 1)
          if (reservation) state.reservations.v4.splice(state.reservations.v4.indexOf(reservation), 1)
        },
      })
    },

    // Plans and jobs
    'GET /plans/{id}': ({ params }) => {
      const held = state.plans.get(params.id)
      if (!held) throw notFound(`plan ${params.id}`)
      if (held.plan.state === 'validated' && isExpired(held.plan)) held.plan.state = 'expired'
      return held.plan
    },
    'POST /plans/{id}/apply': ({ params, body, user, res }) => {
      const out = applyPlan(state, user, params.id, Boolean(body.confirm), emit)
      if (out.code) throw new Problem(out.status, out.code, out.detail)
      res.statusCode = out.status
      return out.body
    },
    'POST /plans/{id}/rollback': ({ params, user }) => {
      const out = rollbackPlan(state, user, params.id, emit)
      if (out.code) throw new Problem(out.status, out.code, out.detail)
      return out.body
    },
    'DELETE /plans/{id}': ({ params }) => {
      if (!state.plans.delete(params.id)) throw notFound(`plan ${params.id}`)
      return null
    },
    'GET /jobs/{id}': ({ params }) => state.jobs.get(params.id) || (() => { throw notFound(`job ${params.id}`) })(),

    // Alerts and series
    'GET /alerts': ({ query }) => {
      const f = (key, value) => !query.get(key) || value === query.get(key)
      const items = state.alerts.filter((a) => f('kind', a.kind) && f('severity', a.severity) && f('state', a.state) && f('node_id', a.node_id) && f('engine', a.engine))
      return paginate(items, query)
    },
    'GET /alerts/summary': () => {
      const open = state.alerts.filter((a) => a.state === 'open')
      const count = (list, key) => list.reduce((acc, a) => ({ ...acc, [a[key]]: (acc[a[key]] || 0) + 1 }), {})
      return { open: open.length, acked: state.alerts.filter((a) => a.state === 'acked').length, by_severity: count(open, 'severity'), by_kind: count(open, 'kind') }
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
    'POST /alerts/consistency/run': ({ res }) => {
      const job = { id: ulid(), plan_id: null, state: 'running', progress: 10, steps: [{ name: 'consistency', state: 'running', output: '', started_at: iso(Date.now()), finished_at: null }], created_at: iso(Date.now()), finished_at: null, error: null }
      state.jobs.set(job.id, job)
      const timer = setTimeout(() => {
        job.state = 'done'
        job.progress = 100
        job.steps[0].state = 'done'
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
            points.push([iso(t), serial, n.is_self ? false : zone.name === 'lab.example.lan.'])
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
      const content = item.engine === 'bind'
        ? '// pelagos:managed\nzone "lab.example.lan" {\n\ttype primary;\n\tfile "db.lab.example.lan";\n};\n'
        : JSON.stringify({ Dhcp4: { 'valid-lifetime': 1800 } }, null, 2)
      return { manifest: { ...item, sha256: { [item.files[0]]: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' } }, files: { [item.files[0]]: content } }
    },

    // Install, import, security
    'GET /install/detect': () => ({
      distro: { id: 'debian', version_id: '13', name: 'Debian GNU/Linux 13 (trixie)', family: 'debian', package_manager: 'apt' },
      engines: {
        bind: { installed: true, version: '9.20.11', service: 'named.service', running: true, config: '/etc/bind/named.conf', paths: { config_dir: '/etc/bind', data_dir: '/var/cache/bind' } },
        kea4: { installed: true, version: '3.2.1', service: 'isc-kea-dhcp4-server.service', running: true, config: '/etc/kea/kea-dhcp4.conf', paths: { config_dir: '/etc/kea' } },
        kea6: { installed: true, version: '3.2.1', service: 'isc-kea-dhcp6-server.service', running: true, config: '/etc/kea/kea-dhcp6.conf', paths: { config_dir: '/etc/kea' } },
        d2: { installed: true, version: '3.2.1', service: 'isc-kea-dhcp-ddns-server.service', running: true, config: '/etc/kea/kea-dhcp-ddns.conf', paths: { config_dir: '/etc/kea' } },
      },
      pelagos: { include_present: true, sockets_ok: true, keys_present: true },
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
    'GET /install/security': () => ({
      findings: [
        { id: 'rndc-md5', kind: 'insecure_key', severity: 'critical', engine: 'bind', subject: 'key:rndc-key', description: 'The rndc key uses hmac-md5.', proposal: 'Regenerate the rndc key with hmac-sha256.', risk: 'rndc restarts briefly; no query impact.' },
        { id: 'kea-shared-key', kind: 'insecure_key', severity: 'warning', engine: 'd2', subject: 'key:kea-ddns', description: 'All nodes share one DDNS key created with hmac-md5.', proposal: 'Add a new hmac-sha256 key to the BIND update-policy, switch D2 on every node, then remove the old key.', risk: 'Updates in flight during the switch are retried.' },
        { id: 'stats-public', kind: 'insecure_listener', severity: 'warning', engine: 'bind', subject: 'statistics-channels', description: 'statistics-channels listens on 0.0.0.0.', proposal: 'Bind it to 127.0.0.1 only.', risk: 'External scrapers lose access.' },
        { id: 'transfer-any', kind: 'insecure_listener', severity: 'info', engine: 'bind', subject: 'zone:partner.example.', description: 'allow-transfer is not restricted on one zone.', proposal: 'Restrict to key ddi-read.', risk: 'None.' },
      ],
    }),
    'POST /install/security/plan': ({ body, user }) => {
      const ids = body.finding_ids || []
      if (!ids.length) throw invalid('finding_ids', 'choose at least one finding')
      const steps = ids.flatMap((id) =>
        id === 'kea-shared-key'
          ? ['add the new key to BIND update-policy', 'switch D2 to the new key on every node', 'remove the old key']
          : [`remediate ${id}`],
      )
      return createPlan(state, user, {
        scope: 'security', engine: null, summary: `apply ${ids.length} security remediation(s)`,
        changes: ids.map((id) => ({ op: 'replace', target: `security/${id}`, before: null, after: null, node_ids: [] })),
        diff: unifiedDiff('key "rndc-key" {\n\talgorithm hmac-md5;\n};', 'key "rndc-key" {\n\talgorithm hmac-sha256;\n};', '/etc/bind/rndc.key'),
        targets: state.nodes.map((n) => n.peer.id), tool: 'named-checkconf', requires_confirmation: true, job: steps,
        apply: () => { state.alerts.filter((a) => a.kind === 'insecure_key').forEach((a) => { a.state = 'resolved'; a.resolved_at = iso(Date.now()) }) },
      })
    },

    // Administration
    'GET /admin/users': () => ({ items: state.users.map((u) => publicUser(u, state)) }),
    'POST /admin/users': ({ body, user, res }) => {
      if (!body.username || !/^[a-z0-9._-]{2,64}$/.test(body.username)) throw invalid('username', 'lowercase letters, digits, dot, dash and underscore')
      if (!body.password || body.password.length < 8) throw invalid('password', 'must be at least 8 characters')
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
      if (!body.password || body.password.length < 8) throw invalid('password', 'must be at least 8 characters')
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
    'PUT /admin/settings': ({ body, user }) => {
      const merge = (target, patch) => {
        for (const [k, v] of Object.entries(patch)) {
          if (v && typeof v === 'object' && !Array.isArray(v) && target[k] && typeof target[k] === 'object') merge(target[k], v)
          else target[k] = v
        }
      }
      merge(state.settings, body)
      auditEntry(state, user, { action: 'settings.update', target: 'settings' })
      return state.settings
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

export function createMockServer({ quiet = false, jobStepMs } = {}) {
  const state = createState()
  if (jobStepMs !== undefined) state.jobStepMs = jobStepMs

  const sessionOf = (req) => {
    const sid = parseCookies(req.headers.cookie).pelagos_session
    const session = sid && state.sessions.get(sid)
    if (!session) return { sid: null, session: null, user: null }
    const record = state.users.find((u) => u.id === session.userId)
    if (!record || !record.enabled) return { sid: null, session: null, user: null }
    return { sid, session, user: { ...record, permissions: permissionsOf(state, record) } }
  }

  const hub = createWsHub({ authenticate: (req) => sessionOf(req).user, nodeId: state.selfId })
  const handlers = buildHandlers(state, hub.emit)
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
      if (!url.pathname.startsWith(`${API}/`)) throw new Problem(404, 'not_found', 'not an API path')
      const path = url.pathname.slice(API.length)
      const route = routeOf(req.method, path)
      if (!route) {
        const otherMethod = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].some((m) => m !== req.method && routeOf(m, path))
        throw otherMethod ? new Problem(405, 'method_not_allowed', `${req.method} not allowed`) : new Problem(404, 'not_found', `no route for ${path}`)
      }
      const raw = await readBody(req)
      let body = {}
      if (raw) {
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
    for (const node of state.nodes) {
      node.last_seen = iso(Date.now())
      hub.emit('nodes', 'status', node)
    }
  }, 15000)
  ticker.unref?.()

  return {
    state,
    server,
    hub,
    listen(port = 8481, host = '127.0.0.1') {
      return new Promise((resolve) => {
        server.listen(port, host, () => resolve(server.address()))
      })
    },
    close() {
      clearInterval(ticker)
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
  const mock = createMockServer({ quiet: args.includes('--quiet') })
  mock.listen(port, host).then((addr) => {
    console.log(`Pelagos mock API on http://${addr.address}:${addr.port}${API} (users: admin/admin, alice/alice, bob/bob + 123456, viewer/viewer)`)
  })
  const stop = () => mock.close().then(() => process.exit(0))
  process.on('SIGINT', stop)
  process.on('SIGTERM', stop)
}
