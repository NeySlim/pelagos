// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// GET /search in the mock: grouped results with the backend's matching rules and permissions.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'
import { needle, score } from './search.mjs'

let mock
let base

async function session(username, password) {
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  })
  const cookie = res.headers.get('set-cookie').split(';')[0]
  return (path) => fetch(`${base}${path}`, { headers: { cookie } }).then(async (r) => ({ status: r.status, data: await r.json() }))
}

beforeAll(async () => {
  mock = createMockServer({ quiet: true })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
})

afterAll(async () => {
  await mock.close()
})

describe('search mock', () => {
  it('matches names by substring, addresses by prefix and hex with or without separators', () => {
    expect(needle('AA:BB-cc').hex).toBe('aabbcc')
    expect(needle('pc1').hex).toBe(null)
    const row = { names: ['pc1.example.lan.'], addresses: ['192.0.2.100'], hexes: ['aabbccddee01'] }
    expect(score(row, needle('192.0.2.100'))).toBe(0)
    expect(score(row, needle('192.0.2'))).toBe(1)
    expect(score(row, needle('0.2.100'))).toBe(null)
    expect(score(row, needle('example'))).toBe(2)
    expect(score(row, needle('cc:dd:ee'))).toBe(2)
  })

  it('answers every group, a lease by partial MAC and a zone by name', async () => {
    const get = await session('admin', 'admin')
    const lease = (await get('/hosts?per_page=500')).data.items.find((h) => h.lease?.hw_address)?.lease
    const partial = lease.hw_address.split(':').slice(1, 4).join(':')
    const { status, data } = await get(`/search?q=${encodeURIComponent(partial)}&limit=50`)
    expect(status).toBe(200)
    expect(Object.keys(data.results).sort()).toEqual(['alerts', 'hosts', 'leases', 'networks', 'nodes', 'records', 'reservations', 'zones'])
    expect(data.results.leases.map((r) => r.label)).toContain(lease.ip_address)
    for (const r of data.results.leases) expect(Object.keys(r).sort()).toEqual(['id', 'kind', 'label', 'route', 'sublabel'])
    const zones = (await get('/search?q=example.lan')).data.results.zones
    expect(zones[0]).toMatchObject({ kind: 'zone', label: 'example.lan.', route: '/dns/zones/example.lan' })
    expect((await get('/search?q=x&limit=0')).status).toBe(400)
  })
})
