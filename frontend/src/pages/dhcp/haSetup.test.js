// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { draftForNodes, draftFromRelationship, promoteDraft, relationshipHealthy, setupBody, validateHaSetup, withMode } from './haSetup'

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
