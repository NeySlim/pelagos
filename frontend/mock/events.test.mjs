// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The live mock: plans take time per node and announce the local apply on `audit` before
// the outcome on `plans`, and every cluster event the UI animates can be produced on demand.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import net from 'node:net'
import { decodeFrames } from './ws.mjs'
import { createMockServer } from './server.mjs'

let mock
let base
let port

async function login(username = 'admin', password = 'admin') {
  const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username, password }) })
  const body = await res.json()
  return { cookie: res.headers.get('set-cookie').split(';')[0], csrf: body.csrf_token }
}

function client(session) {
  return async (method, path, body) => {
    const res = await fetch(`${base}${path}`, {
      method,
      headers: { cookie: session.cookie, 'content-type': 'application/json', 'x-csrf-token': session.csrf },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    return { status: res.status, data: res.status === 204 ? null : await res.json() }
  }
}

const event = (kind, extra = {}) =>
  fetch(`${base}/_mock/events`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind, ...extra }) }).then(async (r) => ({ status: r.status, data: await r.json() }))

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

// A raw WebSocket subscribed to `topics`; returns the received messages and a close().
async function listen(session, topics) {
  const messages = []
  const socket = net.connect(port, '127.0.0.1')
  await new Promise((resolve) => socket.on('connect', resolve))
  socket.write(`GET /api/v1/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${Buffer.from('pelagos-events-key').toString('base64')}\r\nSec-WebSocket-Version: 13\r\nCookie: ${session.cookie}\r\n\r\n`)
  let buffer = Buffer.alloc(0)
  let upgraded = false
  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk])
    if (!upgraded) {
      const end = buffer.indexOf('\r\n\r\n')
      if (end < 0) return
      buffer = buffer.subarray(end + 4)
      upgraded = true
    }
    const { frames, rest } = decodeFrames(buffer)
    buffer = rest
    frames.forEach((f) => messages.push({ ...JSON.parse(f.payload.toString()), at: Date.now() }))
  })
  await sleep(30)
  const payload = Buffer.from(JSON.stringify({ action: 'subscribe', topics }))
  const mask = Buffer.from([7, 1, 3, 9])
  socket.write(Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), mask, Buffer.from(payload.map((b, i) => b ^ mask[i % 4]))]))
  await sleep(30)
  return { messages, close: () => socket.destroy() }
}

beforeAll(async () => {
  mock = createMockServer({ quiet: true, applyNodeMs: 60, transferMs: 150 })
  port = (await mock.listen(0)).port
  base = `http://127.0.0.1:${port}/api/v1`
})

afterAll(async () => {
  await mock.close()
})

describe('live mock', () => {
  it('applies a plan node by node: the local audit entry first, then the outcome', async () => {
    const session = await login()
    const call = client(session)
    const ws = await listen(session, ['audit', 'plans'])
    const plan = (await call('POST', '/dns/zones/example.lan/records/plan', { changes: [{ op: 'add', target: 'example.lan./paced/A', after: { ttl: 60, rdata: ['192.0.2.61'] } }] })).data
    const started = Date.now()
    const applied = await call('POST', `/plans/${plan.id}/apply`, { confirm: false })
    expect(applied.data.state).toBe('applied')
    expect(Date.now() - started).toBeGreaterThanOrEqual(55)
    await sleep(30)
    const audit = ws.messages.find((m) => m.topic === 'audit' && m.data.plan_id === plan.id)
    const outcome = ws.messages.find((m) => m.topic === 'plans' && m.data.plan_id === plan.id)
    expect(audit.data.request).toEqual({ entry: 'node', verb: 'apply' })
    expect(outcome.event).toBe('applied')
    expect(audit.at).toBeLessThanOrEqual(outcome.at)
    // The secondaries lag until their transfer lands.
    const lagging = (await call('GET', '/dns/zones/example.lan')).data.status
    const values = Object.values(lagging).map((s) => s.serial)
    expect(new Set(values).size).toBe(2)
    await sleep(200)
    const caughtUp = (await call('GET', '/dns/zones/example.lan')).data.status
    expect(new Set(Object.values(caughtUp).map((s) => s.serial)).size).toBe(1)
    const rolled = await call('POST', `/plans/${plan.id}/rollback`)
    expect(rolled.data.state).toBe('rolled_back')
    await sleep(30)
    expect(ws.messages.find((m) => m.topic === 'audit' && m.data.request?.verb === 'rollback')?.data.plan_id).toBe(plan.id)
    ws.close()
  })

  it('produces a lease, a pool alert that opens and resolves, and refuses unknown kinds', async () => {
    const session = await login()
    const call = client(session)
    const ws = await listen(session, ['leases', 'alerts'])
    const before = mock.state.leases.v4.length
    const lease = await event('lease')
    expect(lease.data.ok).toBe(true)
    expect(mock.state.leases.v4.length).toBe(before + 2)
    const opened = await event('alert')
    await sleep(30)
    expect(ws.messages.find((m) => m.topic === 'alerts' && m.event === 'opened')?.data.id).toBe(opened.data.id)
    expect(ws.messages.find((m) => m.topic === 'leases')?.data.new_since_last).toBe(1)
    const series = (await call('GET', '/series/pools?engine=kea4&subnet_id=3&step=300')).data.series[0]
    const [, assigned, total] = series.points[series.points.length - 1]
    expect(assigned).toBe(total)
    await event('alert-resolve')
    await sleep(30)
    expect(mock.state.alerts.find((a) => a.id === opened.data.id).state).toBe('resolved')
    expect(ws.messages.find((m) => m.topic === 'alerts' && m.event === 'resolved' && m.data.id === opened.data.id)).toBeTruthy()
    expect((await event('nothing')).status).toBe(404)
    ws.close()
  })

  it('runs a replication round, an HA failover with a growing queue and its failback', async () => {
    const session = await login()
    const ws = await listen(session, ['ha'])
    const self = mock.state.nodes.find((n) => n.is_self)
    const peer = mock.state.nodes.find((n) => !n.is_self)
    const version = self.config_version
    await event('replication', { delayMs: 40 })
    expect(self.config_version).toBe(version + 1)
    expect(peer.config_version).toBe(version)
    await sleep(80)
    expect(peer.config_version).toBe(version + 1)

    mock.state.unsentMs = 20
    await event('ha-failover')
    const primary = mock.state.ha.v4[0]
    expect(primary.state).toBe('partner-down')
    expect(primary.partner.in_touch).toBe(false)
    await sleep(120)
    expect(primary.unsent_update_count).toBeGreaterThan(1)
    await event('ha-failback')
    expect(primary.state).toBe('hot-standby')
    expect(primary.unsent_update_count).toBe(0)
    const sample = '2026-01-01T00:00:00Z'
    mock.state.ha.v4[1].collected_at = sample
    await event('heartbeat')
    expect(mock.state.ha.v4[1].collected_at).not.toBe(sample)
    // State changes go out on `ha`; a heartbeat sample alone does not.
    await sleep(30)
    const changes = ws.messages.filter((m) => m.topic === 'ha').length
    expect(changes).toBeGreaterThan(3)
    await event('heartbeat')
    await sleep(30)
    expect(ws.messages.filter((m) => m.topic === 'ha').length).toBe(changes)
    ws.close()
  })
})
