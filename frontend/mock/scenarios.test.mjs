// SPDX-License-Identifier: Apache-2.0
// @vitest-environment node
// The mock's clusters of three and four nodes: a Kea HA pair with backups, BIND secondaries on
// every peer, the relationship read, maintenance on the pair, the HA setup and secondaries plans,
// and the switch between scenarios that the e2e tests use.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { createMockServer } from './server.mjs'

let mock
let base

async function session() {
  const res = await fetch(`${base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'admin' }) })
  const body = await res.json()
  const cookie = res.headers.get('set-cookie').split(';')[0]
  return async (method, path, data) => {
    const r = await fetch(`${base}${path}`, {
      method,
      headers: { cookie, 'content-type': 'application/json', 'x-csrf-token': body.csrf_token },
      body: data === undefined ? undefined : JSON.stringify(data),
    })
    return { status: r.status, data: r.status === 204 ? null : await r.json() }
  }
}

beforeAll(async () => {
  mock = createMockServer({ quiet: true, scenario: 'three' })
  const addr = await mock.listen(0)
  base = `http://127.0.0.1:${addr.port}/api/v1`
})

afterAll(async () => {
  await mock.close()
})

const ids = () => mock.state.nodeIds

describe('mock clusters of more than two nodes', () => {
  it('serves three nodes, a pair and a backup', async () => {
    const call = await session()
    const nodes = (await call('GET', '/nodes')).data.items
    expect(nodes.map((n) => n.peer.name)).toEqual(['ns1', 'ns2', 'ns3'])
    expect(nodes[2].peer.modules).toMatchObject({ bind: true, kea4: true, kea6: false })
    const ha = (await call('GET', '/dhcp/v4/ha')).data
    expect(ha.items.map((h) => h.role)).toEqual(['primary', 'standby', 'backup'])
    const [rel] = ha.relationships
    expect(rel.backups).toEqual(['ns3'])
    expect(rel.servers.find((s) => s.name === 'ns3')).toMatchObject({ role: 'backup', state: 'backup', node_name: 'ns3', partner: null })
    expect((await call('GET', '/dhcp/v6/ha')).data.relationships[0].servers).toHaveLength(2)
    // Every DHCPv4 server holds the leases, the backup included.
    const copies = (await call('GET', '/dhcp/v4/leases/192.0.2.100')).data.items
    expect(copies.map((l) => l.node_id).sort()).toEqual([ids().ns1, ids().ns2, ids().ns3].sort())
  })

  it('applies maintenance on the partner and refuses a backup', async () => {
    const call = await session()
    const plan = (await call('POST', '/dhcp/v4/ha/maintenance/plan', { node_id: ids().ns2, action: 'start' })).data
    expect(plan.target_node_ids).toEqual([ids().ns1])
    const refused = await call('POST', '/dhcp/v4/ha/maintenance/plan', { node_id: ids().ns3, action: 'start' })
    expect(refused.status).toBe(400)
    expect(refused.data.errors[0].message).toContain('backup')
  })

  it('builds the HA setup and secondaries plans with one change per node', async () => {
    const call = await session()
    const servers = ['ns1', 'ns2', 'ns3'].map((name, i) => ({ name, url: `http://${name}.example.lan:8001/`, role: ['primary', 'secondary', 'backup'][i], node_id: ids()[name] }))
    const plan = (await call('POST', '/dhcp/v4/ha/setup/plan', { mode: 'load-balancing', servers })).data
    expect(plan.target_node_ids).toEqual([ids().ns1, ids().ns2, ids().ns3])
    expect(plan.changes.map((c) => c.node_ids[0])).toEqual(plan.target_node_ids)
    const bad = await call('POST', '/dhcp/v4/ha/setup/plan', { mode: 'hot-standby', servers })
    expect(bad.status).toBe(400)
    const applied = await call('POST', `/plans/${plan.id}/apply`, { confirm: true })
    expect(applied.data.results).toHaveLength(3)
    expect((await call('GET', '/dhcp/v4/ha')).data.relationships[0].mode).toBe('load-balancing')

    const drop = (await call('POST', '/dns/zones/example.lan/secondaries/plan', { node_ids: [ids().ns2] })).data
    expect(drop.requires_confirmation).toBe(true)
    expect(drop.target_node_ids).toEqual([ids().ns1, ids().ns3])
    await call('POST', `/plans/${drop.id}/apply`, { confirm: true })
    const zone = (await call('GET', '/dns/zones/example.lan')).data
    expect(Object.keys(zone.copies)).toEqual([ids().ns1, ids().ns2])
    expect(zone.status[ids().ns3].error).toContain('not configured')
  })

  it('switches to four nodes, the last backup out of sync', async () => {
    const res = await fetch(`${base}/_mock/scenario`, { method: 'POST', body: JSON.stringify({ name: 'four' }) })
    expect((await res.json()).nodes).toEqual(['ns1', 'ns2', 'ns3', 'ns4'])
    const call = await session()
    expect((await call('GET', '/dhcp/v4/ha')).data.relationships[0].backups).toEqual(['ns3', 'ns4'])
    const alerts = (await call('GET', '/alerts?state=open')).data.items
    expect(alerts.some((a) => a.kind === 'ha_backup_out_of_sync' && a.node_id === ids().ns4)).toBe(true)
    const summary = (await call('GET', '/dashboard/summary')).data
    expect(summary.nodes).toHaveLength(4)
    expect((await fetch(`${base}/_mock/scenario`, { method: 'POST', body: JSON.stringify({ name: 'nine' }) })).status).toBe(404)
  })
})

describe('mock Kea 3 hub and spoke', () => {
  it('serves two relationships on the hub, maintenance and setup across them', async () => {
    const res = await fetch(`${base}/_mock/scenario`, { method: 'POST', body: JSON.stringify({ name: 'hub' }) })
    expect((await res.json()).nodes).toEqual(['ns1', 'ns2', 'ns3'])
    const call = await session()
    const ha = (await call('GET', '/dhcp/v4/ha')).data
    expect(ha.items[0].other_relationships.map((h) => h.server_name)).toEqual(['ns1-b'])
    expect(ha.relationships.map((r) => r.servers.map((s) => `${s.name}@${s.node_name}`))).toEqual([
      ['ns1-a@ns1', 'ns2@ns2'],
      ['ns1-b@ns1', 'ns3@ns3'],
    ])
    expect(ha.relationships[0].servers[0].leases).toBeGreaterThan(0)
    const maint = (await call('POST', '/dhcp/v4/ha/maintenance/plan', { node_id: ids().ns1, action: 'start' })).data
    expect(maint.target_node_ids.sort()).toEqual([ids().ns2, ids().ns3].sort())
    const rels = ha.relationships.map((r) => ({ mode: r.mode, servers: r.servers.map(({ name, url, role, node_id }) => ({ name, url, role, node_id })) }))
    const plan = (await call('POST', '/dhcp/v4/ha/setup/plan', { relationships: rels })).data
    expect(plan.target_node_ids).toEqual([ids().ns1, ids().ns2, ids().ns3])
    const clash = structuredClone(rels)
    clash[1].servers[0].url = clash[0].servers[0].url
    const bad = await call('POST', '/dhcp/v4/ha/setup/plan', { relationships: clash })
    expect(bad.status).toBe(400)
    expect(bad.data.errors[0].field).toBe('relationships[1].servers[0].url')
  })

  it('repairs a terminated HA: clocks checked, the primary restarted last', async () => {
    await fetch(`${base}/_mock/scenario`, { method: 'POST', body: JSON.stringify({ name: 'terminated' }) })
    const call = await session()
    const ha = (await call('GET', '/dhcp/v4/ha')).data.items
    expect(ha.map((h) => `${h.server_name}:${h.state}:${h.partner.clock_skew}`)).toEqual(['ns1:terminated:75', 'ns2:terminated:-75'])
    const open = (await call('GET', '/alerts?kind=ha_terminated&state=open')).data.items
    expect(open[0].details.cause).toBe('clock_skew')
    const nodes = (await call('GET', '/nodes')).data.items
    expect(nodes.every((n) => n.clock?.ntp?.synchronized)).toBe(true)
    const plan = (await call('POST', '/dhcp/v4/ha/repair/plan', {})).data
    expect(plan.target_node_ids).toEqual([ids().ns2, ids().ns1])
    expect(plan.state).toBe('validated')
    expect(plan.validations.map((v) => v.tool)).toEqual(['clock', 'clock'])
    expect((await call('POST', `/plans/${plan.id}/apply`, { confirm: true })).status).toBe(200)
    const after = (await call('GET', '/dhcp/v4/ha')).data.items
    expect(after.map((h) => h.state)).toEqual(['hot-standby', 'hot-standby'])
    expect((await call('GET', '/alerts?kind=ha_terminated&state=open')).data.items).toEqual([])
    expect((await call('POST', '/dhcp/v4/ha/repair/plan', {})).status).toBe(409)
  })

  it('compares a backup with its primary in four nodes', async () => {
    await fetch(`${base}/_mock/scenario`, { method: 'POST', body: JSON.stringify({ name: 'four' }) })
    const call = await session()
    const servers = (await call('GET', '/dhcp/v4/ha')).data.relationships[0].servers
    const ns4 = servers.find((s) => s.name === 'ns4')
    expect(ns4.receives_from).toEqual(['ns1', 'ns2'])
    expect(ns4.lease_reference.server).toBe('ns1')
    expect(ns4.leases).toBeLessThan(ns4.lease_reference.leases)
  })
})
