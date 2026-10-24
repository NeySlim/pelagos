// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { dhcpFamily, formatErrorRate } from './summary'

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
