// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The certificate handlers keep working after the e2e hook switches the scenario, which
// empties the state object they filled when the server was created.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'

let mock
let base

beforeAll(async () => {
  mock = createMockServer({ quiet: true })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
})

afterAll(async () => {
  await mock.close()
})

describe('mock certificates after a scenario switch', () => {
  it('lists three nodes', async () => {
    const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) })
    const { csrf_token: csrf } = await res.json()
    const cookie = res.headers.get('set-cookie').split(';')[0]
    const headers = { cookie, 'content-type': 'application/json', 'x-csrf-token': csrf }
    expect((await fetch(`${base}/_mock/scenario`, { method: 'POST', headers, body: JSON.stringify({ name: 'three' }) })).status).toBe(200)
    const overview = await fetch(`${base}/admin/certificates`, { headers })
    expect(overview.status).toBe(200)
    expect((await overview.json()).nodes.map((n) => n.name)).toEqual(['ns1', 'ns2', 'ns3'])
  })
})
