// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { dhcpFamily } from './summary'

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
