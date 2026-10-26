// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { keaSkews, terminatedCauses, terminatedServers } from './haRepair'

const server = (name, st, skew) => ({ server_name: name, state: st, enabled: true, partner: { server_name: name === 'server1' ? 'server2' : 'server1', clock_skew: skew } })

describe('HA terminated', () => {
  it('lists the terminated servers and the skews Kea measured', () => {
    const items = [server('server1', 'terminated', 75), server('server2', 'terminated', -75), server('server3', 'backup', null)]
    expect(terminatedServers(items).map((s) => s.server_name)).toEqual(['server1', 'server2'])
    expect(keaSkews(items)).toEqual([
      { server: 'server1', partner: 'server2', seconds: 75 },
      { server: 'server2', partner: 'server1', seconds: 75 },
    ])
    expect(keaSkews([server('server1', 'terminated', 2)])).toEqual([])
    expect(terminatedServers([{ ...server('server1', 'terminated'), enabled: false }])).toEqual([])
  })

  it('keeps one probable cause per code from the open alerts of the engine', () => {
    const cause = { key: 'alert.ha_cause.clock_skew', params: { seconds: 75, partner: 'server2' } }
    const alert = (engine, state, code) => ({ kind: 'ha_terminated', engine, state, details: { cause: code }, title: 't', title_message: { key: 'alert.ha_terminated', params: { cause } } })
    const causes = terminatedCauses([alert('kea4', 'open', 'clock_skew'), alert('kea4', 'acked', 'clock_skew'), alert('kea6', 'open', 'config'), alert('kea4', 'resolved', 'partner')], 'kea4')
    expect(causes).toEqual([{ code: 'clock_skew', message: cause, title: 't' }])
  })
})
