// SPDX-License-Identifier: Apache-2.0
// Runtime operations of the mock: the same allow-list as services/ops_service.py, with
// per-operation permissions, confirmation, reads on peers and canned daemon answers.

const op = (name, permission, write, params = [], extra = {}) => ({
  name, permission, write, params, required: extra.required || [], confirm: Boolean(extra.confirm), choices: extra.choices || {},
})

export const BIND_OPS = [
  op('status', 'read:dns', false),
  op('zonestatus', 'read:dns', false, ['zone', 'view'], { required: ['zone'] }),
  op('showzone', 'read:dns', false, ['zone', 'view'], { required: ['zone'] }),
  op('fetchlimit', 'read:dns', false, ['view']),
  op('tcp-timeouts', 'read:dns', false),
  op('validation-status', 'read:dns', false, ['view']),
  op('signing-list', 'read:dns', false, ['zone', 'view'], { required: ['zone'] }),
  op('dnssec-status', 'read:dns', false, ['zone', 'view'], { required: ['zone'] }),
  op('serve-stale-status', 'read:dns', false, ['view']),
  op('managed-keys-status', 'read:dns', false, ['view']),
  op('nta-dump', 'read:dns', false, ['view']),
  op('reload', 'ops:dns', true, ['zone', 'view']),
  op('reconfig', 'ops:dns', true),
  op('notify', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('retransfer', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('freeze', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('thaw', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('refresh', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('loadkeys', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('sign', 'ops:dns', true, ['zone', 'view'], { required: ['zone'] }),
  op('trace', 'ops:dns', true, ['level']),
  op('notrace', 'ops:dns', true),
  op('sync', 'ops:dns', true, ['zone', 'view', 'clean']),
  op('flush', 'ops:dns', true, ['view']),
  op('flushname', 'ops:dns', true, ['name', 'view'], { required: ['name'] }),
  op('flushtree', 'ops:dns', true, ['name', 'view'], { required: ['name'] }),
  op('querylog', 'ops:dns', true, ['mode'], { required: ['mode'], choices: { mode: ['on', 'off'] } }),
  op('nta-add', 'ops:dns', true, ['name', 'lifetime', 'view'], { required: ['name'] }),
  op('nta-remove', 'ops:dns', true, ['name', 'view'], { required: ['name'] }),
  op('serve-stale', 'ops:dns', true, ['mode', 'view'], { required: ['mode'], choices: { mode: ['on', 'off', 'reset'] } }),
  op('managed-keys-refresh', 'ops:dns', true, ['view']),
  op('stats', 'ops:dns', true),
  op('dumpdb', 'ops:dns', true),
]

const CFG = 'write:dhcp.config'
const KEA_COMMON = [
  op('status-get', 'read:dhcp', false),
  op('version-get', 'read:dhcp', false),
  op('build-report', 'read:dhcp', false),
  op('list-commands', 'read:dhcp', false),
  op('statistic-get-all', 'read:dhcp', false),
  op('statistic-get', 'read:dhcp', false, ['name'], { required: ['name'] }),
  op('statistic-reset', CFG, true, ['name'], { required: ['name'] }),
  op('statistic-reset-all', CFG, true, [], { confirm: true }),
  op('config-reload', CFG, true, [], { confirm: true }),
]
const KEA_DHCP = [
  op('ha-heartbeat', 'read:dhcp', false, ['server-name']),
  op('ha-sync', 'ops:dhcp.ha', true, ['server-name', 'max-period']),
  op('ha-scopes', 'ops:dhcp.ha', true, ['scopes', 'server-name'], { required: ['scopes'] }),
  op('ha-continue', 'ops:dhcp.ha', true, ['server-name']),
  op('ha-reset', 'ops:dhcp.ha', true, ['server-name'], { confirm: true }),
  op('dhcp-disable', CFG, true, ['max-period'], { confirm: true }),
  op('dhcp-enable', CFG, true),
  op('leases-reclaim', 'ops:dhcp.leases', true, ['remove'], { required: ['remove'] }),
  op('config-backend-pull', CFG, true),
  op('cache-clear', CFG, true, [], { confirm: true }),
  op('cache-flush', CFG, true, ['count'], { confirm: true }),
]
export const KEA_OPS = {
  v4: [...KEA_COMMON, ...KEA_DHCP,
    op('lease4-resend-ddns', 'ops:dhcp.leases', true, ['ip-address'], { required: ['ip-address'] }),
    op('lease4-wipe', 'ops:dhcp.leases', true, ['subnet-id'], { confirm: true })],
  v6: [...KEA_COMMON, ...KEA_DHCP,
    op('lease6-resend-ddns', 'ops:dhcp.leases', true, ['ip-address'], { required: ['ip-address'] }),
    op('lease6-wipe', 'ops:dhcp.leases', true, ['subnet-id'], { confirm: true })],
  d2: KEA_COMMON,
}
// What the mock daemons offer: no host cache, no config backend, no lease wipe in Kea 3.
const UNAVAILABLE = new Set(['cache-clear', 'cache-flush', 'config-backend-pull', 'lease4-wipe', 'lease6-wipe'])

function bindOutput(name, params) {
  switch (name) {
    case 'status':
      return 'version: BIND 9.20.0 (Stable Release)\nrunning on localhost: Linux x86_64\nnumber of zones: 4 (0 automatic)\nserver is up and running\n'
    case 'zonestatus':
      return `name: ${params.zone}\ntype: primary\nfiles: ${params.zone}.db\nserial: 2026102401\ndynamic: yes\n`
    case 'flushname':
    case 'flushtree':
      return ''
    default:
      return `${name}: done\n`
  }
}

function keaResult(name, family) {
  if (name === 'status-get') return { pid: 4242, uptime: 86400, reload: 3600, 'multi-threading-enabled': true }
  if (name === 'version-get') return { extended: '3.2.1' }
  if (name === 'list-commands') return KEA_OPS[family].map((o) => o.name).filter((n) => !UNAVAILABLE.has(n))
  if (name === 'statistic-get-all') return { 'pkt4-received': [[1234, '2026-10-24 10:00:00.000']] }
  if (name === 'ha-heartbeat') return { state: 'hot-standby', 'date-time': 'Sat, 24 Oct 2026 10:00:00 GMT' }
  return {}
}

export function opsHandlers(state, { Problem, invalid, hasPermission, auditEntry }) {
  const check = (spec, body, user) => {
    if (!hasPermission(user, spec.permission)) throw new Problem(403, 'forbidden', `requires ${spec.permission}`)
    const params = body.params || {}
    for (const key of Object.keys(params)) if (!spec.params.includes(key)) throw invalid(key, `not a parameter of ${spec.name}`)
    for (const key of spec.required) if (params[key] === undefined || params[key] === '') throw invalid(key, 'required')
    for (const [key, allowed] of Object.entries(spec.choices)) {
      if (params[key] !== undefined && !allowed.includes(params[key])) throw invalid(key, `one of ${allowed.join(', ')}`)
    }
    if (spec.confirm && body.confirm !== true) throw new Problem(428, 'confirmation_required', `${spec.name} needs confirm=true`)
    const target = body.node_id || state.selfId
    if (target !== state.selfId && spec.write) {
      throw new Problem(501, 'not_supported', `${spec.name} changes the daemon: run it on that node (log in there)`)
    }
    return { params, target }
  }
  const keaCatalog = (family, query) => ({
    node_id: query.get('node_id') || state.selfId,
    family,
    error: null,
    operations: KEA_OPS[family].map((o) => ({ ...o, available: !UNAVAILABLE.has(o.name) })),
  })
  const keaRun = (family, { body, user }) => {
    const spec = KEA_OPS[family].find((o) => o.name === body.command)
    if (!spec) throw invalid('command', `${body.command} is not an allowed operation for ${family}`)
    const { params, target } = check(spec, body, user)
    if (UNAVAILABLE.has(spec.name)) throw new Problem(409, 'conflict', `'${spec.name}' command not supported`)
    const engine = family === 'd2' ? 'd2' : family === 'v4' ? 'kea4' : 'kea6'
    if (spec.write) auditEntry(state, user, { action: 'dhcp.ops', target: `${engine}:${spec.name}`, engine, request: { op: spec.name, ...params } })
    return { command: spec.name, family, node_id: target, result: keaResult(spec.name, family) }
  }
  return {
    'GET /dns/ops': () => ({ node_id: state.selfId, operations: BIND_OPS }),
    'POST /dns/ops': ({ body, user }) => {
      const spec = BIND_OPS.find((o) => o.name === body.op)
      if (!spec) throw invalid('op', `unknown operation ${body.op}`)
      const { params, target } = check(spec, body, user)
      if (spec.write) auditEntry(state, user, { action: 'dns.ops', target: `bind:${spec.name}`, engine: 'bind', request: { op: spec.name, ...params } })
      return { op: spec.name, node_id: target, output: bindOutput(spec.name, params) }
    },
    'GET /dhcp/{family}/ops': ({ params, query }) => keaCatalog(params.family, query),
    'POST /dhcp/{family}/ops': (ctx) => keaRun(ctx.params.family, ctx),
    'GET /dhcp/d2/ops': ({ query }) => keaCatalog('d2', query),
    'POST /dhcp/d2/ops': (ctx) => keaRun('d2', ctx),
  }
}
