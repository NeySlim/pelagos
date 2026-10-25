// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { dhcpFamily, formatErrorRate, mergePools } from './summary'
import { alertForPool } from '../../lib/trace'

describe('dhcpFamily', () => {
  it('prefers v4 when a node runs kea-dhcp4', () => {
    expect(dhcpFamily({ nodes: [{ peer: { modules: { kea4: true, kea6: true } } }] })).toBe('v4')
    expect(dhcpFamily({})).toBe('v4')
  })

  it('opens v6 when only kea-dhcp6 runs', () => {
    expect(dhcpFamily({ nodes: [{ peer: { modules: { kea6: true } } }] })).toBe('v6')
    expect(dhcpFamily({ engines: { kea6: { running: true } } })).toBe('v6')
  })

  it('ignores an engine whose capabilities call failed', () => {
    expect(dhcpFamily({ engines: { kea4: { running: false, error: 'down' }, kea6: { running: true } } })).toBe('v6')
  })
})

describe('formatErrorRate', () => {
  it('rounds to one decimal in the UI language', () => {
    expect(formatErrorRate(3, 1000, 'en')).toBe('0.3')
    expect(formatErrorRate(3, 1000, 'fr')).toBe('0,3')
    expect(formatErrorRate(0, 0, 'fr')).toBe('0')
    expect(formatErrorRate(1, 3, 'en')).toBe('33.3')
  })
})

describe('mergePools', () => {
  // What GET /dashboard/summary returns on the lab pair: each Kea server of the HA pair
  // reports the same pools from its own lease table (the standby lags by a lease or two).
  const row = (node_id, subnet_id, pool, assigned, total) => ({
    node_id, engine: 'kea4', subnet_id, subnet: '192.0.2.0/24', pool, assigned, total, percent: (assigned / total) * 100,
  })
  const lab = [
    row('NS1', 1, '192.0.2.100 - 192.0.2.199', 12, 100),
    row('NS1', 1, '192.0.2.200 - 192.0.2.219', 19, 20),
    row('NS2', 1, '192.0.2.100 - 192.0.2.199', 13, 100),
    row('NS2', 1, '192.0.2.200-192.0.2.219', 18, 20),
    { ...row('NS1', 1, '2001:db8::100 - 2001:db8::1ff', 3, 256), engine: 'kea6' },
  ]

  it('shows each pool of an HA pair once, with the worst value of the pair', () => {
    const out = mergePools(lab)
    expect(out.map((p) => [p.engine, p.pool, p.assigned])).toEqual([
      ['kea4', '192.0.2.200 - 192.0.2.219', 19],
      ['kea4', '192.0.2.100 - 192.0.2.199', 13],
      ['kea6', '2001:db8::100 - 2001:db8::1ff', 3],
    ])
    expect(out[0].node_ids).toEqual(['NS1', 'NS2'])
    expect(out[0].node_id).toBe('NS1')
    expect(out[1].node_id).toBe('NS2')
    expect(out[2].node_ids).toEqual(['NS1'])
    expect(mergePools(null)).toEqual([])
  })

  it('keeps the alerts of either server on the merged pool', () => {
    const [guest] = mergePools(lab)
    const alert = { kind: 'pool_full', subject: 'kea4:subnet:1:pool:192.0.2.200-192.0.2.219', node_id: 'NS2' }
    expect(alertForPool(alert, guest)).toBe(true)
    expect(alertForPool({ ...alert, node_id: 'NS3' }, guest)).toBe(false)
  })
})
