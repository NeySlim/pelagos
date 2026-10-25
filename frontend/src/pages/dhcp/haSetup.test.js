// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { addRelationship, asSetup, backupGap, draftForNodes, draftFromRelationship, draftFromRelationships, flattenHa, promoteDraft, relPrefix, relationshipHealthy, setupBody, setupRequest, validateHaSetup, validateSetup, withMode } from './haSetup'

const server = (name, role, extra = {}) => ({ name, role, url: `http://${name}.example.lan:8001/`, node_id: name.toUpperCase(), ...extra })
const draft = (mode, ...roles) => ({ mode, servers: roles.map((r, i) => server(`ns${i + 1}`, r)) })

describe('HA relationship form', () => {
  it('takes a pair with any number of backups, per Kea mode', () => {
    expect(validateHaSetup(draft('hot-standby', 'primary', 'standby'))).toEqual({})
    expect(validateHaSetup(draft('hot-standby', 'primary', 'standby', 'backup', 'backup', 'backup', 'backup', 'backup', 'backup'))).toEqual({})
    expect(validateHaSetup(draft('load-balancing', 'secondary', 'primary', 'backup'))).toEqual({})
    expect(validateHaSetup(draft('passive-backup', 'primary', 'backup', 'backup'))).toEqual({})
  })

  it('refuses what Kea refuses', () => {
    expect(validateHaSetup(draft('hot-standby', 'primary', 'primary')).servers).toBe('ha.setup.errors.roleCount')
    expect(validateHaSetup(draft('hot-standby', 'primary', 'secondary'))['servers[1].role']).toBe('ha.setup.errors.role')
    expect(validateHaSetup(draft('passive-backup', 'primary', 'primary')).servers).toBe('ha.setup.errors.roleCount')
    expect(validateHaSetup({ mode: 'passive-backup', servers: [server('ns1', 'primary'), server('ns2', 'primary')] }).role).toBe('primary')
    expect(validateHaSetup(draft('hot-standby', 'primary')).servers).toBe('ha.setup.errors.twoServers')
    const d = draft('hot-standby', 'primary', 'standby', 'backup')
    d.servers[1].name = 'ns1'
    d.servers[2].url = 'ns3:8001'
    d.servers[2].node_id = 'NS1'
    expect(validateHaSetup(d)).toMatchObject({
      'servers[1].name': 'ha.setup.errors.duplicate',
      'servers[2].url': 'ha.setup.errors.url',
      'servers[2].node_id': 'ha.setup.errors.nodeTwice',
    })
    const none = draft('hot-standby', 'primary', 'standby')
    none.servers.forEach((s) => (s.node_id = ''))
    expect(validateHaSetup(none).servers).toBe('ha.setup.errors.noNode')
  })

  it('drafts the pair and backups from the nodes running the family', () => {
    const node = (id, name, self, kea6 = true) => ({ is_self: self, peer: { id, name, url: `https://${name}.example.lan:8444`, modules: { kea4: true, kea6 } } })
    const d = draftForNodes([node('B', 'ns2', false), node('A', 'ns1', true), node('C', 'ns3', false, false)], 'v6')
    expect(d.servers.map((s) => `${s.name}:${s.role}:${s.url}`)).toEqual(['ns1:primary:http://ns1.example.lan:8002/', 'ns2:standby:http://ns2.example.lan:8002/'])
    expect(draftForNodes([node('A', 'ns1', true), node('B', 'ns2', false), node('C', 'ns3', false)], 'v4').servers.map((s) => s.role)).toEqual(['primary', 'standby', 'backup'])
  })

  it('follows a mode change with the roles', () => {
    const d = draft('hot-standby', 'primary', 'standby', 'backup')
    expect(withMode(d, 'load-balancing').servers.map((s) => s.role)).toEqual(['primary', 'secondary', 'backup'])
    expect(withMode(d, 'passive-backup').servers.map((s) => s.role)).toEqual(['primary', 'backup', 'backup'])
  })

  it('promotes a backup into the role of the lost server', () => {
    const rel = {
      mode: 'hot-standby',
      servers: [
        { ...server('ns1', 'primary'), state: 'partner-down', in_touch: true },
        { ...server('ns2', 'standby'), state: 'unavailable', in_touch: false },
        { ...server('ns3', 'backup'), state: 'backup' },
        { ...server('ns4', 'backup'), state: 'backup' },
      ],
    }
    expect(promoteDraft(rel, 'ns4').servers.map((s) => `${s.name}:${s.role}`)).toEqual(['ns1:primary', 'ns2:backup', 'ns3:backup', 'ns4:standby'])
    // The lost server keeps its place in the peer list but no node: nothing is written on it.
    expect(promoteDraft(rel, 'ns4').servers.map((s) => s.node_id)).toEqual(['NS1', '', 'NS3', 'NS4'])
    const healthy = { ...rel, servers: rel.servers.map((s) => ({ ...s, state: 'backup', in_touch: true })) }
    expect(promoteDraft(healthy, 'ns3').servers[1]).toMatchObject({ role: 'backup', node_id: 'NS2' })
    expect(draftFromRelationship(rel).servers).toHaveLength(4)
    expect(relationshipHealthy(rel)).toBe(false)
    rel.servers[0].state = rel.servers[1].state = 'hot-standby'
    rel.servers[1].in_touch = true
    expect(relationshipHealthy(rel)).toBe(true)
    rel.servers[3].state = 'waiting'
    expect(relationshipHealthy(rel)).toBe(false)
  })

  it('sends only what the API takes', () => {
    const d = draft('hot-standby', 'primary', 'standby')
    d.servers[1].node_id = ''
    d.servers[0].auto_failover = false
    expect(setupBody(d)).toEqual({
      mode: 'hot-standby',
      servers: [
        { name: 'ns1', url: 'http://ns1.example.lan:8001/', role: 'primary', node_id: 'NS1', auto_failover: false },
        { name: 'ns2', url: 'http://ns2.example.lan:8001/', role: 'standby' },
      ],
    })
  })
})

describe('Kea 3 hub and spoke setup', () => {
  const rel = (mode, ...servers) => ({ mode, servers })
  const hubDraft = () => ({
    relationships: [
      rel('hot-standby', server('hub-a', 'standby', { node_id: 'HUB', url: 'http://hub.example.lan:8001/' }), server('spoke1', 'primary')),
      rel('hot-standby', server('hub-b', 'standby', { node_id: 'HUB', url: 'http://hub.example.lan:8003/' }), server('spoke2', 'primary')),
    ],
  })

  it('takes one node in several relationships, each server under its own name and URL', () => {
    expect(validateSetup(hubDraft())).toEqual({})
    expect(setupRequest(hubDraft())).toEqual({ relationships: hubDraft().relationships.map(setupBody) })
    // One relationship keeps the shape every node version takes.
    expect(setupRequest({ relationships: [hubDraft().relationships[0]] })).toEqual(setupBody(hubDraft().relationships[0]))
  })

  it('refuses a name or a URL used in two relationships, prefixing fields as the API does', () => {
    const d = hubDraft()
    d.relationships[1].servers[0].name = 'hub-a'
    d.relationships[1].servers[0].url = 'http://hub.example.lan:8001'
    expect(validateSetup(d)).toEqual({
      'relationships[1].servers[0].name': 'ha.setup.errors.nameElsewhere',
      'relationships[1].servers[0].url': 'ha.setup.errors.urlElsewhere',
    })
    d.relationships[1].servers[1].role = 'standby'
    expect(validateSetup(d)['relationships[1].servers']).toBe('ha.setup.errors.roleCount')
  })

  it('adds a relationship with the hub on a new port', () => {
    const d = addRelationship({ relationships: [draft('hot-standby', 'primary', 'standby')] }, 'v4')
    expect(d.relationships).toHaveLength(2)
    expect(d.relationships[1].servers[0]).toMatchObject({ name: 'ns1-2', url: 'http://ns1.example.lan:8003/', role: 'standby', node_id: 'NS1' })
    expect(relPrefix(d, 1)).toBe('relationships[1].')
    expect(draftFromRelationships([draft('hot-standby', 'primary', 'standby')]).relationships).toHaveLength(1)
    expect(asSetup(draft('hot-standby', 'primary', 'standby')).relationships).toHaveLength(1)
  })

  it('flattens a hub into one state per relationship', () => {
    const items = [{ node_id: 'HUB', server_name: 'hub-a', other_relationships: [{ server_name: 'hub-b', enabled: true }] }, { node_id: 'S1', server_name: 'spoke1' }]
    expect(flattenHa(items).map((h) => `${h.node_id}:${h.server_name}`)).toEqual(['HUB:hub-a', 'HUB:hub-b', 'S1:spoke1'])
  })

  it('measures a backup against its primary like the alert does', () => {
    expect(backupGap({ leases: 98, lease_reference: { server: 'ns1', leases: 100 } })).toEqual({ diff: 2, inStep: true })
    expect(backupGap({ leases: 90, lease_reference: { server: 'ns1', leases: 100 } })).toEqual({ diff: 10, inStep: false })
    expect(backupGap({ leases: 4950, lease_reference: { server: 'ns1', leases: 5000 } }).inStep).toBe(true)
    expect(backupGap({ leases: null, lease_reference: { server: 'ns1', leases: 1 } })).toBeNull()
    expect(backupGap({ leases: 3 })).toBeNull()
  })
})
