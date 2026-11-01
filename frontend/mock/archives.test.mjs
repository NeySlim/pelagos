// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The archive handlers keep their state after the e2e hook switches the scenario, which empties
// the state object they filled when the server was created; scheduling waits for a tested key.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'

let mock
let base
let headers

beforeAll(async () => {
  mock = createMockServer({ quiet: true })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
  const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) })
  const { csrf_token: csrf } = await res.json()
  headers = { cookie: res.headers.get('set-cookie').split(';')[0], 'content-type': 'application/json', 'x-csrf-token': csrf }
})

afterAll(async () => {
  await mock.close()
})

const call = (method, path, body) => fetch(`${base}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined })
const IDENTITY = `AGE-SECRET-KEY-1${'Q'.repeat(58)}`

describe('mock archives', () => {
  it('serves the nodes of the new scenario and keeps changes after a switch', async () => {
    expect((await call('POST', '/_mock/scenario', { name: 'three' })).status).toBe(200)
    const overview = await (await call('GET', '/admin/archives')).json()
    expect(overview.nodes.map((n) => n.name)).toEqual(['ns1', 'ns2', 'ns3'])
    const list = await (await call('GET', '/admin/archives/list')).json()
    expect(new Set(list.items.map((x) => x.node_name))).toEqual(new Set(['ns1', 'ns2', 'ns3']))
    const created = await call('POST', '/admin/archives/destinations', { type: 'mounted', name: 'USB', params: { path: '/mnt/usb' } })
    expect(created.status).toBe(201)
    const after = await (await call('GET', '/admin/archives')).json()
    expect(after.destinations.map((d) => d.name)).toContain('USB')
  })

  it('refuses to schedule until a private key is tested', async () => {
    expect((await call('POST', '/_mock/scenario', { name: 'three' })).status).toBe(200)
    const operator = `age1${'q'.repeat(58)}`
    let r = await call('POST', '/admin/archives/identity', { op: 'remove_recipient', recipient: (await (await call('GET', '/admin/archives')).json()).recipients[0].recipient })
    expect(r.status).toBe(200)
    expect((await call('POST', '/admin/archives/identity', { op: 'add_recipient', recipient: operator, label: 'safe' })).status).toBe(200)
    r = await call('PUT', '/admin/archives/settings', { schedule_enabled: true })
    expect(r.status).toBe(409)
    expect((await r.json()).code).toBe('archive_key_unverified')
    r = await call('PUT', '/admin/settings', { archives: { schedule_enabled: true } })
    expect(r.status).toBe(409)
    r = await call('POST', `/admin/archives/keys/${operator}/verify`, { identity: 'nope' })
    expect(r.status).toBe(400)
    r = await call('POST', `/admin/archives/keys/${operator}/verify`, { identity: IDENTITY })
    expect(r.status).toBe(200)
    expect((await r.json()).recipient.verified_at).toBeTruthy()
    expect((await call('PUT', '/admin/archives/settings', { schedule_enabled: true })).status).toBe(200)
  })
})
