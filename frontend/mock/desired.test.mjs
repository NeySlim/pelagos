// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// Desired state verbs of the mock: convergence, idempotence, dry_run, If-Match and confirmation.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'
import { covers } from './desired.mjs'

let mock
let base
let call

beforeAll(async () => {
  mock = createMockServer({ quiet: true, jobStepMs: 5 })
  base = `http://127.0.0.1:${(await mock.listen(0)).port}/api/v1`
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin' }),
  })
  const login = await res.json()
  const cookie = res.headers.get('set-cookie').split(';')[0]
  call = async (method, path, body, headers = {}) => {
    const r = await fetch(`${base}${path}`, {
      method,
      headers: { cookie, 'x-csrf-token': login.csrf_token, 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
    return { status: r.status, data: r.status === 204 ? null : await r.json(), etag: r.headers.get('etag') }
  }
})

afterAll(async () => {
  await mock.close()
})

describe('desired state verbs', () => {
  it('compares only the fields the body gives', () => {
    expect(covers({ a: 1, b: [{ x: 1, y: 2 }] }, { b: [{ x: 1 }] })).toBe(true)
    expect(covers({ a: 1 }, { a: 2 })).toBe(false)
    expect(covers({ tags: [] }, { tags: null })).toBe(true)
  })

  it('converges an RRset, then answers changed false', async () => {
    const url = '/dns/zones/example.lan/rrsets/desired/A'
    const dry = await call('PUT', `${url}?dry_run=1`, { ttl: 300, records: ['192.0.2.77'] })
    expect(dry.status).toBe(200)
    expect(dry.data.changed).toBe(true)
    expect(dry.data.plan.changes[0].op).toBe('add')
    expect((await call('GET', url)).status).toBe(404)
    const put = await call('PUT', url, { ttl: 300, records: ['192.0.2.77'] })
    expect(put.data.changed).toBe(true)
    expect(put.data.result.state).toBe('applied')
    const read = await call('GET', url)
    expect(read.data.rdata).toEqual(['192.0.2.77'])
    expect((await call('PUT', url, { ttl: 300, records: ['192.0.2.77'] })).data.changed).toBe(false)
    expect((await call('PUT', url, { records: ['192.0.2.78'] }, { 'if-match': '"0"' })).status).toBe(412)
    expect((await call('PUT', url, { records: ['192.0.2.78'] }, { 'if-match': read.etag })).data.changed).toBe(true)
    expect((await call('DELETE', url)).data.changed).toBe(true)
    expect((await call('DELETE', url)).data.changed).toBe(false)
    expect((await call('PUT', url, { records: ['192.0.2.1'], rdata: [] })).status).toBe(400)
    expect((await call('PUT', '/dhcp/v4/options/dhcp4/6', { data: '192.0.2.1', 'csv-format': true })).status).toBe(400)
  })

  it('converges a reservation and asks confirmation where the plan does', async () => {
    const url = '/dhcp/v4/reservations/hw-address=aa:bb:cc:dd:ee:77'
    const want = { subnet_id: 1, ip_address: '192.0.2.77', hostname: 'desired' }
    expect((await call('PUT', url, want)).data.changed).toBe(true)
    expect((await call('PUT', url, want)).data.changed).toBe(false)
    expect((await call('GET', `${url}?subnet_id=1`)).data.hostname).toBe('desired')
    const zone = await call('DELETE', '/dns/zones/example.lan')
    expect(zone.status).toBe(428)
    expect(zone.data.plan.changes[0].op).toBe('delete')
    expect((await call('DELETE', `${url}?subnet_id=1&confirm=1`)).data.changed).toBe(true)
    expect((await call('DELETE', `${url}?subnet_id=1`)).data.changed).toBe(false)
  })
})
