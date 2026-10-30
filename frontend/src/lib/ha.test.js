// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { dhcpServiceState, partnerLost } from './ha'

describe('partnerLost', () => {
  it('counts communication-interrupted while still in touch', () => {
    expect(partnerLost({ in_touch: true, communication_interrupted: true })).toBe(true)
    expect(partnerLost({ in_touch: false })).toBe(true)
    expect(partnerLost({ in_touch: true, communication_interrupted: false })).toBe(false)
    expect(partnerLost(null)).toBe(false)
  })
})

describe('dhcpServiceState', () => {
  it('reads dhcp-state from status-get', () => {
    expect(dhcpServiceState({ 'dhcp-state': { 'globally-disabled': false, 'disabled-by-user': false } })).toEqual({ enabled: true, userDisabled: false })
    expect(dhcpServiceState({ 'dhcp-state': { 'globally-disabled': true, 'disabled-by-user': true } })).toEqual({ enabled: false, userDisabled: true })
    expect(dhcpServiceState({ 'dhcp-state': { 'globally-disabled': true, 'disabled-by-user': false } })).toEqual({ enabled: false, userDisabled: false })
    expect(dhcpServiceState({ pid: 1 })).toEqual({ enabled: undefined, userDisabled: undefined })
  })
})
