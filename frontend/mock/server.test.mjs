// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The mock answers every endpoint of the spec with the documented shapes,
// enforces sessions, CSRF and RBAC, and runs the plan lifecycle.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { createMockServer } from './server.mjs'
import { decodeFrames } from './ws.mjs'
import { ENDPOINTS } from '../src/services/endpoints.js'

let mock
let base
let port

async function login(username, password, totp_code) {
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password, ...(totp_code ? { totp_code } : {}) }),
  })
  const body = await res.json()
  if (res.status !== 200) return { status: res.status, body }
  const cookie = res.headers.get('set-cookie').split(';')[0]
  return { status: 200, body, cookie, csrf: body.csrf_token }
}

function client(session) {
  return async (method, path, body, { csrf = true } = {}) => {
    const headers = { cookie: session.cookie, 'content-type': 'application/json' }
    if (csrf) headers['x-csrf-token'] = session.csrf
    const res = await fetch(`${base}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    const type = res.headers.get('content-type') || ''
    const data = res.status === 204 ? null : /application\/(problem\+)?json/.test(type) ? await res.json() : await res.text()
    return { status: res.status, data, type }
  }
}

beforeAll(async () => {
  mock = createMockServer({ quiet: true, jobStepMs: 5 })
  const addr = await mock.listen(0)
  port = addr.port
  base = `http://127.0.0.1:${port}/api/v1`
})

afterAll(async () => {
  await mock.close()
})

// Concrete arguments for each path placeholder and a valid body per write.
function concrete(spec, state) {
  const zone = 'example.lan'
  const userId = state.users.find((u) => u.username === 'viewer')?.id
  const audit = state.audit[0].id
  const history = state.history[0].id
  return spec
    .split(' ')[1]
    .replace('{family}', 'v4')
    .replace('{category}', 'ads')
    .replace('{zone}', zone)
    .replace('{name}', spec.includes('/keys/') ? 'ddi-admin' : 'helpdesk')
    .replace('{ip}', '192.0.2.100')
    .replace('{key}', 'ip:192.0.2.10')
    .replace(/\{id\}/, () => {
      if (spec.includes('/nodes/')) return state.nodeIds.ns2
      if (spec.includes('/admin/certificates/')) return state.nodeIds.ns2
      if (spec.includes('/admin/notifications/channels/')) return 'ch-ntfy'
      if (spec.includes('/admin/archives/destinations/')) return 'dst-peer'
      if (spec.includes('/admin/archives/')) return state.archives.list[0].id
      if (spec.includes('/admin/users/')) return userId
      if (spec.includes('/audit/')) return audit
      if (spec.includes('/advanced/history/')) return history
      if (spec.includes('/subnets/')) return '1'
      if (spec.includes('/alerts/')) return state.alerts[0].id
      return 'unknown'
    })
}

const BODIES = {
  'POST /admin/notifications/channels': { type: 'gotify', name: 'Gotify', params: { url: 'https://gotify.example.lan' }, secrets: { token: 'app-token' } },
  'POST /admin/notifications/test': { channel_id: 'ch-ntfy' },
  'PUT /admin/notifications/order': (state) => ({ node_ids: state.nodes.map((n) => n.peer.id).reverse() }),
  'PUT /admin/notifications/mute': () => ({ until: new Date(Date.now() + 3600000).toISOString(), comment: 'maintenance' }),
  'POST /admin/archives/destinations': { type: 'mounted', name: 'NAS', params: { path: '/mnt/backup' } },
  'POST /admin/archives/destinations/test': { destination_id: 'dst-peer' },
  'POST /admin/archives/identity': { op: 'prune_retired' },
  'PUT /admin/archives/settings': { start_time: '02:30' },
  'POST /admin/archives/{id}/restore/plan': { parts: ['pelagos.settings:settings'] },
  'POST /dhcp/ddns/failover/plan': (state) => ({ to_node_id: state.nodeIds.ns2 }),
  'POST /dhcp/ddns/switchover/plan': (state) => ({ to_node_id: state.nodeIds.ns2 }),
  'POST /dns/resolver/fallback/plan': { preset: 'quad9', forward: 'first', hours: 24 },
  'PUT /dns/resolver/fallback': () => ({ until: new Date(Date.now() + 3600000).toISOString() }),
  'POST /install/kea-migration/analyze': { series: '3.2', source: 'isc' },
  'PUT /admin/ipv6': { prefixes: ['2001:db8:1::/64'] },
  'POST /admin/ipv6/sources/test': { source_id: 'src-router' },
  'POST /dhcp/{family}/ha/setup/plan': { remove: true },
  'POST /dns/zones/{zone}/secondaries/plan': { node_ids: [] },
  'POST /auth/password': { current_password: 'admin', new_password: 'Admin-new-password-1' },
  'POST /auth/totp/confirm': { code: '123456' },
  'DELETE /auth/totp': { password: 'Admin-new-password-1' },
  'PUT /account/preferences': { language: 'fr' },
  'PUT /dashboard/layout': { layout: [{ i: 'ha', x: 0, y: 0, w: 4, h: 3 }] },
  'POST /dns/zones/plan': { change: { op: 'add', target: '_default/new.example.lan.', after: { name: 'new.example.lan.', kind: 'primary', file: 'db.new', ns: ['ns1.example.lan.'] } } },
  'POST /dns/zones/{zone}/records/plan': { changes: [{ op: 'add', target: 'example.lan./api/A', after: { ttl: 300, rdata: ['192.0.2.90'] } }] },
  'POST /dns/zones/{zone}/retransfer': { node_id: 'x' },
  'POST /dns/config/plan': { changes: [{ op: 'replace', target: 'options/recursion', after: 'no' }] },
  'POST /dns/keys/plan': { change: { op: 'add', after: { name: 'new-key', algorithm: 'hmac-sha256' } } },
  'POST /dns/acls/plan': { change: { op: 'add', after: { name: 'lab', elements: ['192.0.2.0/28'] } } },
  'POST /dns/resolver/plan': { forwarders: ['192.0.2.1'] },
  'PUT /dns/rpz/categories/{category}': { level: 'light', action: 'nodata' },
  'PUT /dns/rpz/subscriptions/{id}': { url: 'https://lists.example.com/l.txt', format: 'hosts' },
  'PUT /dns/rpz/order': { order: [] },
  'POST /dns/rpz/estimate': { category: 'ads', level: 'light' },
  'POST /dns/rpz/allow': { domain: 'ok.example.com' },
  'POST /dns/rpz/exempt': { cidr: '192.0.2.7' },
  'POST /dns/catalog-zones/{zone}/members/plan': { op: 'add', member: 'new.example.lan' },
  'POST /dns/dnssec/policies/plan': { change: { op: 'add', target: 'dnssec-policy/slow', after: { statements: [{ name: 'keys', value: '{ csk lifetime unlimited algorithm ecdsap256sha256; }' }] } } },
  'POST /dns/zones/{zone}/dnssec/plan': { action: 'rollover', key_id: 48217 },
  'POST /dhcp/{family}/subnets/plan': { change: { op: 'add', after: { subnet: '192.0.2.224/28' } } },
  'POST /dhcp/{family}/shared-networks/plan': { change: { op: 'add', after: { name: 'lab' } } },
  'POST /dhcp/{family}/client-classes/plan': { change: { op: 'add', after: { name: 'printers', test: "option[60].text == 'printer'" } } },
  'POST /dhcp/{family}/options/plan': { changes: [{ op: 'add', target: 'option-data/dhcp4/time-offset', after: { name: 'time-offset', code: 2, data: '3600' } }] },
  'POST /dhcp/{family}/reservations/plan': { change: { op: 'add', after: { subnet_id: 1, identifier: '02:00:5e:00:99:99', ip_address: '192.0.2.99', hostname: 'new' } } },
  'POST /dhcp/{family}/ha/maintenance/plan': { action: 'start' },
  'POST /dhcp/{family}/ha/repair/plan': {},
  'POST /dhcp/{family}/service/plan': { enable: false },
  'POST /dhcp/{family}/ddns/plan': { changes: [{ op: 'replace', target: 'ddns-update-on-renew', after: true }] },
  'POST /dhcp/{family}/hooks/plan': { changes: [{ op: 'replace', target: 'hooks-libraries', after: [] }] },
  'POST /dhcp/{family}/config/plan': { config: { Dhcp4: {} } },
  'POST /dhcp/d2/config/plan': { config: { DhcpDdns: {} } },
  'POST /dns/ops': { op: 'status' },
  'POST /dhcp/{family}/ops': { command: 'status-get' },
  'POST /dhcp/d2/ops': { command: 'status-get' },
  'POST /dhcp/{family}/config/adopt/plan': { source: 'running' },
  'POST /dhcp/d2/config/adopt/plan': { source: 'file' },
  'POST /hosts/plan': { hostname: 'printer2', ip: '192.0.2.43', mac: '02:00:5e:00:aa:01', zone: 'example.lan', reservation: true, subnet_id: 1 },
  'POST /plans/{id}/apply': { confirm: true },
  'POST /alerts/{id}/ack': { comment: 'known' },
  'POST /alerts/exceptions': { kind: 'ptr_mismatch', key: '192.0.2.106|pc7.example.lan.', comment: 'kept on purpose' },
  'POST /dns/ptr/coverage': { addresses: ['192.0.2.106'], name: 'pc7.example.lan.' },
  'POST /dns/ptr/orphans/plan': { delete: [{ zone: '2.0.192.in-addr.arpa.', name: '106.2.0.192.in-addr.arpa.', target: 'workstation7.example.lan.' }] },
  'POST /install/plan': { engines: ['bind'], source: 'distro' },
  'POST /install/import/plan': { engines: ['bind', 'kea4'] },
  'POST /install/security/plan': { finding_ids: ['bind:weak_rndc_key:rndc-key'] },
  'POST /install/security/ha-guard/plan': { peers: ['192.0.2.12'] },
  'POST /admin/users': { username: 'carol', password: 'Carol-password-1', roles: ['viewer'] },
  'PUT /admin/users/{id}': { enabled: false },
  'POST /admin/users/{id}/reset-password': { password: 'Another-password-1' },
  'POST /admin/roles': { name: 'auditor', permissions: ['read:audit'] },
  'PUT /admin/roles/{name}': { description: 'changed' },
  'PUT /admin/settings': { plans: { ttl_seconds: 900 } },
  'PUT /admin/modules': { cluster: { dhcpv6: true } },
  'PUT /admin/certificates/cluster': { source: 'acme', acme: { profile: 'letsencrypt-staging' }, apply: false },
  'PUT /admin/certificates/{id}/source': { source: 'self_signed' },
  'POST /admin/certificates/{id}/check': { cert_pem: '-----BEGIN CERTIFICATE-----', key_pem: 'key' },
  'POST /admin/certificates/{id}/upload': { cert_pem: '-----BEGIN CERTIFICATE-----', key_pem: 'key' },
}

// Query strings of endpoints that take their input there.
const QUERIES = {
  'GET /dns/rpz/why': '?domain=ads.example.com',
  'DELETE /dns/rpz/allow': '?domain=ok.example.com',
  'DELETE /dns/rpz/exempt': '?cidr=192.0.2.7/32',
}

// Endpoints whose success status is not 200/201/202/204 with these inputs.
const EXPECTED = {
  'POST /dns/zones/{zone}/retransfer': 409, // example.lan is a primary zone
  'POST /admin/archives/upload': 400, // a JSON body, not multipart
  'POST /dns/catalog-zones/{zone}/members/plan': 404, // example.lan is not a catalog
  'POST /dhcp/{family}/ha/maintenance/plan': 404, // node_id missing on purpose
  'POST /dhcp/{family}/ha/repair/plan': 409, // no server is terminated in the pair scenario
  'POST /dhcp/{family}/service/plan': 404,
  'GET /plans/{id}': 404,
  'POST /plans/{id}/apply': 404,
  'POST /plans/{id}/rollback': 404,
  'DELETE /plans/{id}': 404,
  'GET /jobs/{id}': 404,
  'POST /dhcp/d2/config/plan': 409, // the mock D2 file diverges until adopted
  'DELETE /alerts/exceptions/{id}': 404, // an alert id, not an exception id
  'POST /dhcp/ddns/failover/plan': 409, // nothing prepared, the primary answers
  'POST /dhcp/ddns/switchover/plan': 409, // nothing prepared
  'POST /dhcp/ddns/replay/plan': 409, // no outage: no lease lacks its records
  'POST /dns/resolver/fallback/return/plan': 409, // no fallback is active
  'PUT /dns/resolver/fallback': 409, // no fallback is active
}

describe('mock server PTR and exceptions', () => {
  it('adds the PTR to a record plan, lists orphans and ignores an object', async () => {
    const admin = client(await login('admin', 'admin'))
    const cov = await admin('POST', '/dns/ptr/coverage', { addresses: ['192.0.2.106', '198.51.200.1'], name: 'kiosk2.example.lan.' })
    expect(cov.data.items[0]).toMatchObject({ covered: true, reverse_zone: '2.0.192.in-addr.arpa.', conflict: true, current: ['workstation7.example.lan.'] })
    expect(cov.data.items[1]).toMatchObject({ covered: false, reason: 'no_reverse_zone' })
    const plan = await admin('POST', '/dns/zones/example.lan/records/plan', { changes: [{ op: 'add', target: 'example.lan./kiosk2/A', after: { ttl: 300, rdata: ['192.0.2.106'] } }], ptr: { sync: true, delete: true } })
    expect(plan.data.changes.map((c) => c.target)).toEqual(['example.lan./kiosk2.example.lan./A', '2.0.192.in-addr.arpa./106.2.0.192.in-addr.arpa./PTR'])
    expect(plan.data.requires_confirmation).toBe(true)
    const orphans = await admin('GET', '/dns/ptr/orphans')
    const item = orphans.data.items.find((i) => i.ip === '192.0.2.106')
    expect(item).toMatchObject({ target: 'workstation7.example.lan.', category: 'orphan', fix: 'create_a', exception_key: '192.0.2.106|workstation7.example.lan.' })
    const alert = mock.state.alerts.find((a) => a.kind === 'ptr_mismatch')
    expect((await admin('POST', '/alerts/exceptions', { kind: 'ptr_mismatch', key: '192.0.2.106|pc7.example.lan.' })).status).toBe(400)
    const created = await admin('POST', '/alerts/exceptions', { kind: 'ptr_mismatch', key: alert.details.exception_keys[0], comment: 'kept on purpose' })
    expect(created.status).toBe(201)
    expect(alert.state).toBe('resolved')
    expect((await admin('GET', '/alerts/exceptions')).data.items.map((e) => e.id)).toContain(created.data.id)
    expect((await admin('DELETE', `/alerts/exceptions/${created.data.id}`)).status).toBe(204)
  })

  it('ignores a health check alert but never an outage', async () => {
    const admin = client(await login('admin', 'admin'))
    expect((await admin('POST', '/alerts/exceptions', { kind: 'ha_terminated', key: 'ha:kea4', comment: 'no' })).status).toBe(400)
    const alert = mock.state.alerts.find((a) => a.kind === 'insecure_key')
    const created = await admin('POST', '/alerts/exceptions', { kind: 'insecure_key', key: alert.details.exception_keys[0], comment: 'legacy key, rotated next month' })
    expect(created.status).toBe(201)
    expect(alert.state).toBe('resolved')
  })
})

describe('mock server notifications, archives and DDNS failover', () => {
  it('returns secrets as booleans and needs both permissions for failover plans', async () => {
    const admin = client(await login('admin', 'admin'))
    const created = await admin('POST', '/admin/notifications/channels', { type: 'webhook', name: 'Hook', params: { url: 'https://hook.example.lan' }, secrets: { hmac_secret: 's3cret' } })
    expect(created.status).toBe(201)
    expect(created.data.secrets).toEqual({ hmac_secret: true })
    expect(JSON.stringify((await admin('GET', '/admin/notifications')).data)).not.toContain('s3cret')
    const moved = await admin('PUT', `/admin/notifications/channels/${created.data.id}`, { params: { url: 'https://other.example.lan' } })
    expect(moved.status).toBe(400)
    const merged = await admin('PUT', `/admin/notifications/channels/${created.data.id}`, { schedule: { reminder_hours: 0 } })
    expect(merged.data.schedule).toMatchObject({ reminder_hours: 0, send_resolved: true })
    const history = await admin('GET', '/admin/notifications/history?alert_id=A1')
    expect(history.data.items[0]).toMatchObject({ channel_id: 'ch-ntfy', result: 'ok', reason: 'events' })
    expect((await admin('GET', '/admin/notifications/history?alert_id=nope')).data.total).toBe(0)
    const ids = await admin('POST', '/admin/archives/identity', { op: 'add_recipient', recipient: 'age1' + 'q'.repeat(58), label: 'offline' })
    expect(ids.data.recipients.map((r) => r.kind)).toEqual(['cluster', 'operator'])
    const dns = client(await login('alice', 'alice'))
    expect((await dns('POST', '/dhcp/ddns/failover/plan', { to_node_id: mock.state.nodeIds.ns2 })).status).toBe(403)
  })

  it('walks prepare, outage, promotion, return and replay like the real service', async () => {
    const admin = client(await login('admin', 'admin'))
    const { ns1, ns2 } = mock.state.nodeIds
    const res = await admin('GET', '/dhcp/ddns/resilience')
    expect(Object.keys(res.data).sort()).toEqual(['d2', 'offline', 'outage', 'replay', 'zones'])
    const zone = (data, name) => data.zones.find((z) => z.zone === name)
    expect(zone(res.data, 'example.lan.').blockers[0]).toMatchObject({ key: 'ddns.blocker.not_managed', params: { zone: 'example.lan.', node: 'ns1' } })
    expect(zone(res.data, '100.51.198.in-addr.arpa.').blockers[0].key).toBe('ddns.blocker.no_transfer')
    expect(zone(res.data, 'corp.example.lan.')).toMatchObject({ view: 'internal', ready: false, epoch: 0, primary_node_id: ns1, copies: [ns2], stale: [], prepared_at: null })
    expect(res.data.replay).toMatchObject({ source: 'default', candidates: 0, notes: [] })
    expect(res.data.d2[0].domains[0].servers[0]).toMatchObject({ node_id: ns1, role: 'primary', port: 53 })
    expect((await admin('POST', '/dhcp/ddns/resilience/plan', { zones: ['example.lan'] })).status).toBe(400)
    const prep = await admin('POST', '/dhcp/ddns/resilience/plan', {})
    expect(prep.data.summary_message).toMatchObject({ key: 'plan.ddns.prepare', params: { count: 2 } })
    expect((await admin('POST', `/plans/${prep.data.id}/apply`, {})).status).toBeLessThan(300)
    await new Promise((r) => setTimeout(r, 100))
    const ready = await admin('GET', '/dhcp/ddns/resilience')
    expect(zone(ready.data, 'corp.example.lan.')).toMatchObject({ ready: true, epoch: 1, blockers: [] })
    expect(ready.data.d2[0].domains.find((d) => d.name === 'corp.example.lan.').servers.map((s) => s.role)).toEqual(['primary', 'secondary'])
    expect((await admin('POST', '/dhcp/ddns/resilience/plan', {})).status).toBe(409)
    expect((await admin('POST', '/dhcp/ddns/failover/plan', { to_node_id: ns2 })).status).toBe(409)
    const switchover = await admin('POST', '/dhcp/ddns/switchover/plan', { to_node_id: ns2, zones: ['internal/corp.example.lan.'] })
    expect(switchover.data).toMatchObject({ scope: 'dns.failover', requires_confirmation: true })
    expect(switchover.data.changes[0].target).toBe('op:freeze/internal/corp.example.lan.')
    await fetch(`${base}/_mock/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'ddns-outage' }) })
    const down = await admin('GET', '/dhcp/ddns/resilience')
    expect(down.data.outage.zones).toContain('internal/corp.example.lan.')
    expect(down.data.replay).toMatchObject({ source: 'open', candidates: 3 })
    expect(mock.state.alerts.find((a) => a.kind === 'ddns_outage' && a.state === 'open').details).toMatchObject({ cause: 'named_down', remediation: 'ddns_failover' })
    expect((await admin('POST', '/dhcp/ddns/switchover/plan', { to_node_id: ns2 })).status).toBe(409)
    const plan = await admin('POST', '/dhcp/ddns/failover/plan', {})
    expect(plan.data.summary_message).toMatchObject({ key: 'plan.ddns.failover', params: { node: 'ns2', previous: 'ns1', epoch: 2 } })
    expect((await admin('POST', `/plans/${plan.data.id}/apply`, { confirm: true })).status).toBeLessThan(300)
    await new Promise((r) => setTimeout(r, 100))
    await fetch(`${base}/_mock/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'ddns-return' }) })
    const back = await admin('GET', '/dhcp/ddns/resilience')
    expect(zone(back.data, 'corp.example.lan.')).toMatchObject({ primary_node_id: ns2, epoch: 2, stale: [ns1] })
    expect(back.data.replay).toMatchObject({ source: 'outage', candidates: 3 })
    expect(mock.state.alerts.some((a) => a.kind === 'dns_stale_primary' && a.state === 'open')).toBe(true)
    expect((await admin('POST', '/dhcp/ddns/replay/plan', { from: '2020-01-01T00:00:00Z', to: '2020-02-01T00:00:00Z' })).status).toBe(400)
    const replay = await admin('POST', '/dhcp/ddns/replay/plan', { limit: 2 })
    expect(replay.data).toMatchObject({ scope: 'dhcp.lease', requires_confirmation: true })
    expect(replay.data.changes).toHaveLength(2)
    expect(replay.data.validations.some((v) => v.output_message?.key === 'ddns.replay.more')).toBe(true)
    await fetch(`${base}/_mock/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'ddns-demote' }) })
    expect(zone((await admin('GET', '/dhcp/ddns/resilience')).data, 'corp.example.lan.').stale).toEqual([])
    delete mock.state.ddnsFailover
  })
})

describe('mock server notification sends', () => {
  it('lends stored secrets to an unsaved test, limits tests, filters history by alert, raises notification_failed', async () => {
    const admin = client(await login('admin', 'admin'))
    mock.state.notify.tests = {}
    const unsaved = { type: 'ntfy', name: 'Phone', language: 'en', params: { url: 'https://unreachable.example.lan', topic: 'pelagos' } }
    const failed = await admin('POST', '/admin/notifications/test', { ...unsaved, scope: 'ch-ntfy' })
    expect(failed.status).toBe(200)
    expect(failed.data).toMatchObject({ ok: false })
    expect(failed.data.error).toContain('unreachable.example.lan')
    for (let i = 0; i < 5; i += 1) {
      const sent = await admin('POST', '/admin/notifications/test', { channel_id: 'ch-ntfy' })
      expect(sent.data, JSON.stringify(sent.data)).toMatchObject({ ok: true })
    }
    expect((await admin('POST', '/admin/notifications/test', { channel_id: 'ch-ntfy' })).status).toBe(429)
    const byAlert = await admin('GET', '/admin/notifications/history?alert_id=ALRT0000000000000000000005')
    expect(byAlert.data.items.map((h) => h.channel_id)).toEqual(['ch-ntfy'])
    expect((await admin('GET', '/admin/notifications/history?result=failed')).data.total).toBe(0)
    expect((await admin('GET', `/admin/notifications/history?from=${new Date(Date.now() + 1000).toISOString()}`)).data.total).toBe(0)

    const res = await fetch(`${base}/_mock/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: 'notify-fail' }) })
    const out = await res.json()
    const overview = (await admin('GET', '/admin/notifications')).data
    expect(overview.channels.find((c) => c.id === 'ch-ntfy').status.state).toBe('failing')
    expect(overview.queue.failing).toBe(1)
    expect((await admin('GET', '/admin/notifications/history?result=failed')).data.items[0]).toMatchObject({ channel_id: 'ch-ntfy', status: 401 })
    const alerts = (await admin('GET', '/alerts?kind=notification_failed&state=open')).data.items
    expect(alerts.map((a) => [a.id, a.subject])).toEqual([[out.id, 'notify:ch-ntfy']])
    expect((await admin('DELETE', '/admin/notifications/mute')).status).toBe(204)
    mock.state.notify.tests = {}
  })
})

describe('mock server resolver, Kea migration and IPv6', () => {
  it('runs a forwarder fallback, extends it, returns, and analyzes the Kea migration', async () => {
    const admin = client(await login('admin', 'admin'))
    const health = await admin('GET', '/dns/resolver/health')
    expect(health.data.nodes[0]).toHaveProperty('latency_ms.p95')
    expect(health.data.presets.map((p) => p.id)).toContain('quad9')
    const plan = await admin('POST', '/dns/resolver/fallback/plan', { preset: 'quad9', forward: 'first', hours: 2 })
    expect(plan.data).toMatchObject({ scope: 'dns.resolver', requires_confirmation: true })
    expect((await admin('POST', `/plans/${plan.data.id}/apply`, { confirm: true })).status).toBe(200)
    expect((await admin('POST', '/dns/resolver/fallback/plan', { preset: 'quad9' })).status).toBe(409)
    const until = new Date(Date.now() + 7200000).toISOString()
    expect((await admin('PUT', '/dns/resolver/fallback', { until })).data.fallback.forwarders).toContain('9.9.9.9')
    const back = await admin('POST', '/dns/resolver/fallback/return/plan', {})
    expect((await admin('POST', `/plans/${back.data.id}/apply`, { confirm: true })).status).toBe(200)
    expect((await admin('GET', '/dns/resolver/health')).data.fallback).toBe(null)
    const report = await admin('POST', '/install/kea-migration/analyze', { series: '3.2', source: 'isc' })
    expect(report.data.findings.every((f) => f.message.key.startsWith('kea_migration.'))).toBe(true)
    expect((await admin('GET', '/install/kea-migration')).data.analysis.id).toBe(report.data.id)
    const viewer = client(await login('viewer', 'viewer'))
    expect((await viewer('GET', '/hosts/ipv6?filter=missing_aaaa')).data.items.map((h) => h.mac)).toEqual(['02:00:5e:00:53:10'])
    expect((await viewer('GET', '/admin/ipv6')).status).toBe(403)
    expect(JSON.stringify((await admin('GET', '/admin/ipv6')).data)).not.toContain('"k"')
  })
})

describe('mock server settings', () => {
  it('validates like the backend registry and accepts former names', async () => {
    const admin = client(await login('admin', 'admin'))
    const schema = (await admin('GET', '/admin/settings/schema')).data
    expect(schema.settings.some((s) => s.key === 'checks.ha_grace_seconds')).toBe(true)
    let r = await admin('PUT', '/admin/settings', { checks: { pool_warning_percent: 99 }, rpz: { categories: {} }, nope: 1 })
    expect(r.status).toBe(400)
    expect(r.data.errors.map((e) => e.field).sort()).toEqual(['checks.pool_warning_percent', 'nope', 'rpz.categories'])
    r = await admin('PUT', '/admin/settings', { alerts_d2_error_rate: 0.02, plan_ttl_seconds: 900 })
    expect(r.status).toBe(200)
    expect(r.data.checks.d2_error_percent).toBe(2)
    expect(r.data.plans.ttl_seconds).toBe(900)
    expect(r.data.plan_ttl_seconds).toBeUndefined()
    r = await admin('PUT', '/admin/settings', { dns: { view_keys: { inside: 'ddi-inside', lab: 'lab-key' } } })
    r = await admin('PUT', '/admin/settings', { dns: { view_keys: { inside: 'ddi-inside' } } })
    expect(r.data.dns.view_keys).toEqual({ inside: 'ddi-inside' })
  })
})

describe('mock server', () => {
  it('blocks D2 writes while its file diverges, until a side is adopted', async () => {
    const admin = client(await login('admin', 'admin'))
    const status = await admin('GET', '/dhcp/d2/config/file')
    expect(status.data.items[0]).toMatchObject({ diverged: true, path: '/etc/kea/kea-dhcp-ddns.conf' })
    const blocked = await admin('POST', '/dhcp/d2/config/plan', { config: {} })
    expect(blocked.status).toBe(409)
    expect(blocked.data.code).toBe('config_divergence')
    const plan = await admin('POST', '/dhcp/d2/config/adopt/plan', { source: 'running' })
    expect(plan.data).toMatchObject({ requires_confirmation: true, scope: 'd2.config' })
    const applied = await admin('POST', `/plans/${plan.data.id}/apply`, { confirm: true })
    expect(applied.data.state).toBe('applied')
    expect((await admin('GET', '/dhcp/d2/config/file')).data.items[0].diverged).toBe(false)
    expect((await admin('POST', '/dhcp/d2/config/plan', { config: {} })).status).toBe(200)
    const rolled = await admin('POST', `/plans/${plan.data.id}/rollback`)
    expect(rolled.data.state).toBe('rolled_back')
    expect((await admin('GET', '/dhcp/d2/config/file')).data.items[0].diverged).toBe(true)
  })

  it('pages leases with a cursor', async () => {
    const admin = client(await login('admin', 'admin'))
    const first = await admin('GET', '/dhcp/v4/leases?limit=3')
    expect(first.data.items).toHaveLength(3)
    expect(first.data.meta.next).toBe(first.data.items[2].ip_address)
    const second = await admin('GET', `/dhcp/v4/leases?limit=3&from_address=${first.data.meta.next}`)
    expect(second.data.items[0].ip_address).not.toBe(first.data.items[0].ip_address)
    expect((await admin('GET', '/dhcp/v4/leases?limit=0')).status).toBe(400)
  })

  it('answers anonymous health and refuses the rest without a session', async () => {
    const health = await fetch(`${base}/health`)
    expect(health.status).toBe(200)
    expect((await health.json()).status).toBe('ok')
    const zones = await fetch(`${base}/dns/zones`)
    expect(zones.status).toBe(401)
    expect(zones.headers.get('content-type')).toBe('application/problem+json')
    expect((await zones.json()).code).toBe('unauthenticated')
  })

  it('handles bad credentials and the TOTP step', async () => {
    expect((await login('admin', 'nope')).body.code).toBe('invalid_credentials')
    expect((await login('bob', 'bob')).body.code).toBe('totp_required')
    const ok = await login('bob', 'bob', '123456')
    expect(ok.status).toBe(200)
    expect(ok.body.permissions).toContain('write:dhcp.subnets')
  })

  it('applies the server password policy', async () => {
    const admin = client(await login('admin', 'admin'))
    const short = await admin('POST', '/admin/users', { username: 'weak', password: 'Short-pw1', roles: ['viewer'] })
    expect(short.status).toBe(400)
    const classes = await admin('POST', '/admin/users', { username: 'weak', password: 'onlylowercaseletters', roles: ['viewer'] })
    expect(classes.status).toBe(400)
  })

  it('enforces CSRF on unsafe methods and RBAC per endpoint', async () => {
    const viewer = client(await login('viewer', 'viewer'))
    expect((await viewer('GET', '/dns/zones')).status).toBe(200)
    const noCsrf = await viewer('POST', '/dns/zones/example.lan/records/plan', BODIES['POST /dns/zones/{zone}/records/plan'], { csrf: false })
    expect(noCsrf.data.code).toBe('csrf_failed')
    const forbidden = await viewer('POST', '/dns/zones/example.lan/records/plan', BODIES['POST /dns/zones/{zone}/records/plan'])
    expect(forbidden.status).toBe(403)
    expect(forbidden.data.code).toBe('forbidden')
    expect((await viewer('GET', '/admin/users')).status).toBe(403)
  })

  it('paginates and filters', async () => {
    const call = client(await login('admin', 'admin'))
    const page = await call('GET', '/audit?per_page=10&page=2')
    expect(page.data).toMatchObject({ page: 2, per_page: 10 })
    expect(page.data.items).toHaveLength(10)
    expect(page.data.total).toBeGreaterThan(20)
    // Lease search is an exact lookup (address, MAC, DUID or hostname), as Kea answers it.
    const filtered = await call('GET', '/dhcp/v4/leases?q=pc12.example.lan')
    expect(filtered.data.items.map((l) => l.hostname)).toEqual(['pc12.example.lan'])
    const leases = await call('GET', '/dhcp/v4/leases/192.0.2.157')
    expect(leases.data.items).toHaveLength(1)
  })

  it('runs a record plan through validation, apply and rollback', async () => {
    const call = client(await login('alice', 'alice'))
    const before = (await call('GET', '/dns/zones/example.lan/records?name=e2e&type=A')).data
    expect(before.total).toBe(0)
    const plan = (await call('POST', '/dns/zones/example.lan/records/plan', { changes: [{ op: 'add', target: 'example.lan./e2e/A', after: { ttl: 60, rdata: ['192.0.2.60'] } }] })).data
    expect(plan.state).toBe('validated')
    expect(plan.diff).toContain('+e2e.example.lan. 60 IN A 192.0.2.60')
    expect(plan.preconditions[0].kind).toBe('soa_serial')
    const applied = await call('POST', `/plans/${plan.id}/apply`, { confirm: false })
    expect(applied.data.state).toBe('applied')
    expect((await call('GET', '/dns/zones/example.lan/records?name=e2e&type=A')).data.total).toBe(1)
    expect((await call('POST', `/plans/${plan.id}/apply`, {})).data.code).toBe('plan_state')
    const rolled = await call('POST', `/plans/${plan.id}/rollback`)
    expect(rolled.data.state).toBe('rolled_back')
    expect((await call('GET', '/dns/zones/example.lan/records?name=e2e&type=A')).data.total).toBe(0)
  })

  it('joins v6 leases, reservations, AAAA and ip6.arpa PTR into hosts', async () => {
    const call = client(await login('admin', 'admin'))
    const hosts = (await call('GET', '/hosts?q=v6host1&per_page=500')).data.items
    const host = hosts.find((h) => h.hostname === 'v6host1.example.lan.')
    expect(host.ips).toContain('2001:db8::1000')
    expect(host.lease.family).toBe('v6')
    expect(host.records.map((r) => r.rtype).sort()).toEqual(['AAAA', 'PTR'])
    const router = (await call('GET', '/hosts?q=router6')).data.items[0]
    expect(router.reservation.ip_addresses).toEqual(['2001:db8::100'])
    expect(router.records.map((r) => r.rtype)).toEqual(['AAAA'])
  })

  it('plans an IPv6 host with AAAA, ip6.arpa PTR and a v6 reservation', async () => {
    const call = client(await login('admin', 'admin'))
    const plan = (await call('POST', '/hosts/plan', { hostname: 'cam6', ip: '2001:db8::2a', zone: 'example.lan', mac: '02:00:5e:00:aa:66', reservation: true })).data
    expect(plan.state).toBe('validated')
    expect(plan.changes.map((c) => c.target)).toEqual([
      'example.lan./cam6.example.lan./AAAA',
      '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa./a.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa./PTR',
      'subnet6/1/reservations/hw-address=02:00:5e:00:aa:66',
    ])
    expect((await call('POST', `/plans/${plan.id}/apply`, {})).data.state).toBe('applied')
    const host = (await call('GET', '/hosts?q=cam6')).data.items[0]
    expect(host).toMatchObject({ mac: '02:00:5e:00:aa:66', ips: ['2001:db8::2a'] })
    expect(host.reservation.ip_addresses).toEqual(['2001:db8::2a'])
    expect((await call('POST', `/plans/${plan.id}/rollback`)).data.state).toBe('rolled_back')
    expect((await call('GET', '/hosts?q=cam6')).data.total).toBe(0)
    expect((await call('POST', '/hosts/plan', { hostname: 'x', ip: '2001:db8::zz', zone: 'example.lan' })).status).toBe(400)
  })

  it('rejects invalid rdata at validation and requires confirmation where needed', async () => {
    const call = client(await login('admin', 'admin'))
    const bad = (await call('POST', '/dns/zones/example.lan/records/plan', { changes: [{ op: 'add', target: 'example.lan./x/A', after: { rdata: ['invalid'] } }] })).data
    expect(bad.state).toBe('failed')
    expect(bad.validations[0].ok).toBe(false)
    const lease = (await call('POST', '/dhcp/v4/leases/192.0.2.101/delete/plan')).data
    expect(lease.requires_confirmation).toBe(true)
    expect((await call('POST', `/plans/${lease.id}/apply`, { confirm: false })).status).toBe(428)
    expect((await call('POST', `/plans/${lease.id}/apply`, { confirm: true })).data.state).toBe('applied')
  })

  it('refuses a plan apply once its preconditions moved', async () => {
    const call = client(await login('admin', 'admin'))
    const change = (name) => ({ changes: [{ op: 'add', target: `example.lan./${name}/A`, after: { ttl: 60, rdata: ['192.0.2.61'] } }] })
    const first = (await call('POST', '/dns/zones/example.lan/records/plan', change('pre1'))).data
    const second = (await call('POST', '/dns/zones/example.lan/records/plan', change('pre2'))).data
    expect((await call('POST', `/plans/${first.id}/apply`, {})).data.state).toBe('applied')
    const stale = await call('POST', `/plans/${second.id}/apply`, {})
    expect(stale.status).toBe(409)
    expect(stale.data.code).toBe('precondition_failed')
    const acl = { change: { op: 'add', after: { name: 'pre-acl', elements: ['192.0.2.0/24'] } } }
    const acl2 = { change: { op: 'add', after: { name: 'pre-acl2', elements: ['192.0.2.0/24'] } } }
    const a = (await call('POST', '/dns/acls/plan', acl)).data
    const b = (await call('POST', '/dns/acls/plan', acl2)).data
    expect((await call('POST', `/plans/${a.id}/apply`, {})).data.state).toBe('applied')
    expect((await call('POST', `/plans/${b.id}/apply`, {})).data.code).toBe('precondition_failed')
  })

  it('checks the plan scope permission and the plan owner', async () => {
    const alice = client(await login('alice', 'alice'))
    const plan = (await alice('POST', '/dns/zones/example.lan/records/plan', { changes: [{ op: 'add', target: 'example.lan./own/A', after: { ttl: 60, rdata: ['192.0.2.62'] } }] })).data
    const viewer = client(await login('viewer', 'viewer'))
    expect((await viewer('GET', `/plans/${plan.id}`)).status).toBe(403)
    expect((await viewer('DELETE', `/plans/${plan.id}`)).status).toBe(403)
    const denied = await viewer('POST', `/plans/${plan.id}/apply`, {})
    expect(denied.status).toBe(403)
    expect(denied.data.code).toBe('forbidden')
    const admin = client(await login('admin', 'admin'))
    expect((await admin('GET', `/plans/${plan.id}`)).status).toBe(200)
    expect((await alice('DELETE', `/plans/${plan.id}`)).status).toBe(204)
  })

  it('rate limits failed logins per username', async () => {
    for (let i = 0; i < 5; i += 1) expect((await login('carol-rl', 'nope')).status).toBe(401)
    const limited = await login('carol-rl', 'nope')
    expect(limited.status).toBe(429)
    expect(limited.body.code).toBe('rate_limited')
    expect((await login('admin', 'admin')).status).toBe(200)
  })

  it('answers 400 on a malformed path escape', async () => {
    const call = client(await login('admin', 'admin'))
    const res = await call('GET', '/dns/zones/%E0%A4%A')
    expect(res.status).toBe(400)
    expect(res.data.code).toBe('validation_error')
  })

  it('runs install plans as jobs', async () => {
    const call = client(await login('admin', 'admin'))
    const plan = (await call('POST', '/install/plan', { engines: ['bind'], source: 'isc', isc_series: '3.2' })).data
    const accepted = await call('POST', `/plans/${plan.id}/apply`, {})
    expect(accepted.status).toBe(202)
    expect(accepted.data.steps.length).toBeGreaterThan(2)
    let job = accepted.data
    for (let i = 0; i < 100 && job.state !== 'done'; i += 1) {
      await new Promise((r) => setTimeout(r, 10))
      job = (await call('GET', `/jobs/${job.id}`)).data
    }
    expect(job.state).toBe('done')
    expect(job.progress).toBe(100)
  })

  it('streams the audit export as NDJSON', async () => {
    const call = client(await login('admin', 'admin'))
    const res = await call('GET', '/audit/export')
    expect(res.type).toContain('application/x-ndjson')
    const lines = res.data.trim().split('\n')
    expect(JSON.parse(lines[0]).id).toBeTruthy()
  })

  it('pushes subscribed events over the WebSocket', async () => {
    const session = await login('admin', 'admin')
    const call = client(session)
    const messages = []
    const socket = net.connect(port, '127.0.0.1')
    const key = Buffer.from('pelagos-mock-key').toString('base64')
    await new Promise((resolve) => socket.on('connect', resolve))
    socket.write(`GET /api/v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\nCookie: ${session.cookie}\r\n\r\n`)
    let buffer = Buffer.alloc(0)
    let upgraded = false
    const accept = createHash('sha1').update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest('base64')
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk])
      if (!upgraded) {
        const end = buffer.indexOf('\r\n\r\n')
        if (end < 0) return
        expect(buffer.subarray(0, end).toString()).toContain(accept)
        buffer = buffer.subarray(end + 4)
        upgraded = true
      }
      const { frames, rest } = decodeFrames(buffer)
      buffer = rest
      frames.forEach((f) => messages.push(JSON.parse(f.payload.toString())))
    })
    const send = (obj) => {
      const payload = Buffer.from(JSON.stringify(obj))
      const mask = Buffer.from([1, 2, 3, 4])
      const masked = Buffer.from(payload.map((b, i) => b ^ mask[i % 4]))
      socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, masked]))
    }
    await new Promise((r) => setTimeout(r, 50))
    send({ action: 'subscribe', topics: ['alerts', 'plans'] })
    send({ action: 'ping' })
    await new Promise((r) => setTimeout(r, 50))
    const alert = mock.state.alerts.find((a) => a.state === 'open')
    await call('POST', `/alerts/${alert.id}/ack`, {})
    await new Promise((r) => setTimeout(r, 100))
    socket.destroy()
    expect(messages.find((m) => m.event === 'pong')).toBeTruthy()
    expect(messages.find((m) => m.topic === 'alerts' && m.event === 'acked')?.data.id).toBe(alert.id)
    expect(messages.find((m) => m.topic === 'audit')).toBeUndefined()
  })

  // Last: it changes the admin password and deletes users and nodes.
  it('serves every endpoint of the spec', async () => {
    const session = await login('admin', 'admin')
    const call = client(session)
    const failures = []
    const ordered = [...ENDPOINTS.filter((s) => !s.startsWith('DELETE ')), ...ENDPOINTS.filter((s) => s.startsWith('DELETE ')).reverse()]
    for (const spec of ordered) {
      if (spec === 'POST /auth/login' || spec === 'POST /auth/logout') continue
      const [method] = spec.split(' ')
      const path = concrete(spec, mock.state) + (QUERIES[spec] || '')
      let body = typeof BODIES[spec] === 'function' ? BODIES[spec](mock.state) : BODIES[spec]
      if (spec === 'POST /auth/totp/confirm') await call('POST', '/auth/totp/enroll')
      if (method !== 'GET' && body === undefined) body = {}
      const res = await call(method, path, method === 'GET' ? undefined : body)
      const expected = EXPECTED[spec]
      const okStatus = expected ? res.status === expected : [200, 201, 202, 204].includes(res.status)
      if (!okStatus || res.status === 501) failures.push(`${spec} -> ${res.status} ${JSON.stringify(res.data).slice(0, 160)}`)
    }
    expect(failures).toEqual([])
  })
})
