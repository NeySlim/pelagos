// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// Lease history in the mock: GET /dhcp/{family}/leases/history and GET /hosts/{key}/timeline.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'

let mock
let base
let get

beforeAll(async () => {
  mock = createMockServer({ quiet: true })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin' }),
  })
  const cookie = res.headers.get('set-cookie').split(';')[0]
  get = (path) => fetch(`${base}${path}`, { headers: { cookie } }).then(async (r) => ({ status: r.status, data: await r.json() }))
})

afterAll(async () => {
  await mock.close()
})

describe('lease history mock', () => {
  it('lists events newest first with filters and paging', async () => {
    const all = await get('/dhcp/v4/leases/history')
    expect(all.status).toBe(200)
    expect(all.data.meta).toEqual({ unavailable: [], truncated: false })
    const ts = all.data.items.map((i) => i.ts)
    expect([...ts].sort().reverse()).toEqual(ts)
    const reassign = all.data.items.find((i) => i.event === 'reassign')
    expect(reassign).toBeTruthy()
    const one = await get(`/dhcp/v4/leases/history?ip=${reassign.ip_address}`)
    expect(one.data.items.map((i) => i.event)).toEqual(['reassign', 'delete', 'new'])
    const mac = reassign.hw_address.replace(/:/g, '-').toUpperCase()
    const byMac = await get(`/dhcp/v4/leases/history?mac=${mac}`)
    expect(byMac.data.items.every((i) => i.hw_address === reassign.hw_address)).toBe(true)
    expect((await get('/dhcp/v4/leases/history?mac=zz')).status).toBe(400)
    expect((await get('/dhcp/v4/leases/history?per_page=1')).data.items).toHaveLength(1)
  })

  it('gives a host timeline by key', async () => {
    const all = await get('/dhcp/v4/leases/history')
    const row = all.data.items.find((i) => i.event === 'reassign')
    const res = await get(`/hosts/${encodeURIComponent(`ip:${row.ip_address}`)}/timeline`)
    expect(res.status).toBe(200)
    expect(res.data.items.map((i) => [i.source, i.event])).toEqual([['lease', 'reassign'], ['lease', 'delete'], ['lease', 'new']])
    expect(res.data.meta.key).toBe(`ip:${row.ip_address}`)
    expect((await get('/hosts/zone:x/timeline')).status).toBe(400)
  })
})
