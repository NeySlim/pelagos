// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { api } from './api'
import { apiClient, ApiError, buildQueryString, errorMessage } from './apiClient'
import { ENDPOINTS, matchEndpoint } from './endpoints'

const calls = []

function jsonResponse(status, body, type = 'application/json') {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => (name.toLowerCase() === 'content-type' ? type : null) },
    json: async () => body,
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
    blob: async () => body,
  }
}

beforeEach(() => {
  calls.length = 0
  apiClient.setCsrfToken('csrf-123')
  global.fetch = vi.fn(async (url, config) => {
    calls.push({ url, ...config })
    return jsonResponse(200, { ok: true })
  })
})

// One call per api function, with representative arguments.
const invocations = [
  () => api.meta.health(), () => api.meta.version(), () => api.meta.capabilities(),
  () => api.auth.login('admin', 'pw'), () => api.auth.logout(), () => api.auth.session(),
  () => api.auth.changePassword('a', 'b'), () => api.auth.totpEnroll(), () => api.auth.totpConfirm('123456'),
  () => api.auth.totpDisable('pw'),
  () => api.account.getPreferences(), () => api.account.updatePreferences({ language: 'fr' }),
  () => api.nodes.list(), () => api.nodes.self(), () => api.nodes.get('n1'), () => api.nodes.enrollToken(600),
  () => api.nodes.remove('n2'), () => api.nodes.sync('n2'), () => api.nodes.replication(),
  () => api.dashboard.summary(), () => api.dashboard.getLayout(), () => api.dashboard.saveLayout([]),
  () => api.dns.instances(), () => api.dns.zones({ q: 'ex' }), () => api.dns.zone('example.lan.'),
  () => api.dns.zonePlan({ op: 'add', target: '_default/x.lan.' }), () => api.dns.records('example.lan', { page: 2 }),
  () => api.dns.recordsPlan('example.lan', []), () => api.dns.retransfer('example.lan', 'n1'),
  () => api.dns.notify('example.lan'), () => api.dns.reload('example.lan'), () => api.dns.dnssec('example.lan'),
  () => api.dns.config(), () => api.dns.configPlan([]), () => api.dns.keys(), () => api.dns.keySecret('ddi-admin'),
  () => api.dns.keysPlan({}), () => api.dns.acls(), () => api.dns.aclsPlan({}), () => api.dns.resolver(),
  () => api.dns.resolverPlan({ recursion: true }), () => api.dns.rpz(), () => api.dns.catalogZones(), () => api.dns.catalogMemberPlan('cat.lan', {}), () => api.dns.dnssecPolicies(),
  () => api.dns.dnssecPoliciesPlan({}), () => api.dns.dnssecPlan('example.lan', { action: 'rollover' }), () => api.dns.stats('n1'),
  () => api.dhcp.servers('v4'), () => api.dhcp.subnets('v4'), () => api.dhcp.subnet('v4', 1), () => api.dhcp.subnetPlan('v4', {}),
  () => api.dhcp.sharedNetworks('v6'), () => api.dhcp.sharedNetworkPlan('v6', {}), () => api.dhcp.clientClasses('v4'),
  () => api.dhcp.clientClassPlan('v4', {}), () => api.dhcp.options('v4'), () => api.dhcp.optionsPlan('v4', []),
  () => api.dhcp.reservations('v4', { q: 'pc' }), () => api.dhcp.reservationPlan('v4', {}), () => api.dhcp.leases('v4'),
  () => api.dhcp.lease('v4', '192.0.2.10'), () => api.dhcp.leaseDeletePlan('v4', '192.0.2.10'),
  () => api.dhcp.utilization('v4'), () => api.dhcp.stats('v4'), () => api.dhcp.ha('v4'),
  () => api.dhcp.haMaintenancePlan('v4', 'n1', 'start'), () => api.dhcp.haTransitions('v4', { from: 1 }),
  () => api.dhcp.servicePlan('v4', 'n1', false), () => api.dhcp.ddns('v4'), () => api.dhcp.ddnsPlan('v4', []),
  () => api.dhcp.hooks('v4'), () => api.dhcp.hooksPlan('v4', []), () => api.dhcp.config('v4'), () => api.dhcp.configPlan('v4', {}),
  () => api.d2.servers(), () => api.d2.stats(), () => api.d2.config(), () => api.d2.configPlan({}),
  () => api.dhcp.configFile('v4'), () => api.dhcp.adoptPlan('v4', 'file'), () => api.d2.configFile(), () => api.d2.adoptPlan('running'),
  () => api.hosts.list({ only_inconsistent: true }), () => api.hosts.get('mac:aa:bb:cc:dd:ee:ff'), () => api.hosts.plan({}),
  () => api.plans.get('p1'), () => api.plans.apply('p1', true), () => api.plans.rollback('p1'), () => api.plans.remove('p1'),
  () => api.jobs.get('j1'),
  () => api.alerts.list({ state: 'open' }), () => api.alerts.summary(), () => api.alerts.ack('a1', 'seen'),
  () => api.alerts.runConsistency(),
  () => api.series.pools({ engine: 'kea4' }), () => api.series.serials({ zone: 'example.lan' }), () => api.series.haTransitions(),
  () => api.audit.list({ user: 'admin' }), () => api.audit.get('e1'), () => api.audit.exportEntries({ from: 1 }),
  () => api.advanced.bindGrammar(), () => api.advanced.bindTree(), () => api.advanced.keaSchema('v4'),
  () => api.advanced.history(), () => api.advanced.historyEntry('h1'),
  () => api.ops.bindCatalog(), () => api.ops.bindRun({ op: 'status' }), () => api.ops.keaCatalog('v4'),
  () => api.ops.keaRun('v4', { command: 'status-get' }), () => api.ops.keaCatalog('d2', 'n1'),
  () => api.ops.keaRun('d2', { command: 'status-get' }),
  () => api.install.detect(), () => api.install.plan({ engines: ['bind'], source: 'distro' }),
  () => api.install.importPlan(['bind']), () => api.install.security(), () => api.install.securityPlan(['x']),
  () => api.admin.users(), () => api.admin.createUser({}), () => api.admin.user('u1'), () => api.admin.updateUser('u1', {}),
  () => api.admin.deleteUser('u1'), () => api.admin.resetPassword('u1', 'pw'), () => api.admin.clearTotp('u1'),
  () => api.admin.roles(), () => api.admin.createRole({}), () => api.admin.updateRole('r', {}), () => api.admin.deleteRole('r'),
  () => api.admin.permissions(), () => api.admin.settings(), () => api.admin.updateSettings({}),
  () => api.admin.modules(), () => api.admin.updateModules({}),
]

describe('api.js', () => {
  it('covers every endpoint of architecture section 17', async () => {
    for (const call of invocations) await call()
    const hit = new Set()
    for (const c of calls) {
      const path = c.url.replace(/^\/api\/v1/, '')
      const spec = matchEndpoint(c.method, path)
      expect(spec, `${c.method} ${path} is not in the spec`).toBeTruthy()
      hit.add(spec)
    }
    const missing = ENDPOINTS.filter((spec) => !hit.has(spec))
    expect(missing).toEqual([])
  })

  it('sends the CSRF token on unsafe methods only', async () => {
    await api.dns.zones()
    await api.plans.apply('p1', true)
    const [get, post] = calls
    expect(get.headers['X-CSRF-Token']).toBeUndefined()
    expect(post.headers['X-CSRF-Token']).toBe('csrf-123')
    expect(JSON.parse(post.body)).toEqual({ confirm: true })
  })

  it('strips the trailing dot of zone names in paths', async () => {
    await api.dns.records('example.lan.', { type: 'A', page: 1 })
    expect(calls[0].url).toBe('/api/v1/dns/zones/example.lan/records?type=A&page=1')
  })

  it('turns problem documents into ApiError', async () => {
    global.fetch = vi.fn(async () =>
      jsonResponse(409, { code: 'precondition_failed', detail: 'serial moved', errors: [{ field: 'x', message: 'bad' }] }, 'application/problem+json'),
    )
    const err = await api.plans.apply('p1').catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err.status).toBe(409)
    expect(err.code).toBe('precondition_failed')
    expect(errorMessage(err)).toBe('serial moved: x bad')
  })

  it('announces a lost session on 401 outside the auth endpoints', async () => {
    global.fetch = vi.fn(async () => jsonResponse(401, { code: 'unauthenticated' }, 'application/problem+json'))
    const listener = vi.fn()
    window.addEventListener('pelagos:unauthenticated', listener)
    await api.dns.zones().catch(() => {})
    await api.auth.session().catch(() => {})
    window.removeEventListener('pelagos:unauthenticated', listener)
    expect(listener).toHaveBeenCalledTimes(1)
  })

  it('keeps the session on a 401 invalid_credentials from the account endpoints', async () => {
    global.fetch = vi.fn(async () => jsonResponse(401, { code: 'invalid_credentials' }, 'application/problem+json'))
    const listener = vi.fn()
    window.addEventListener('pelagos:unauthenticated', listener)
    const err = await apiClient.post('/auth/password', { current_password: 'typo', new_password: 'x' }).catch((e) => e)
    window.removeEventListener('pelagos:unauthenticated', listener)
    expect(err.code).toBe('invalid_credentials')
    expect(listener).not.toHaveBeenCalled()
  })

  it('builds query strings without empty values', () => {
    expect(buildQueryString({ a: 1, b: '', c: null, d: [1, 2], e: false })).toBe('?a=1&d=1&d=2&e=false')
    expect(buildQueryString({})).toBe('')
  })
})
