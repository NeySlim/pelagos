// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { formatOffset, ntpState, skewFloor, skewTone } from './clock'

describe('node clock', () => {
  it('formats offsets with their sign', () => {
    expect(formatOffset(0.0123)).toBe('+0.012 s')
    expect(formatOffset(-42)).toBe('-42.0 s')
    expect(formatOffset(null)).toBe('-')
  })

  it('compares the lower bound of the measurement with the thresholds', () => {
    expect(skewFloor({ offset: 5.5, uncertainty: 1 })).toBe(4.5)
    expect(skewTone({ offset: 0.2, uncertainty: 0.01 })).toBe('success')
    expect(skewTone({ offset: -7.3, uncertainty: 0.02 })).toBe('warning')
    // A slow exchange never turns a reading into a warning.
    expect(skewTone({ offset: 5.5, uncertainty: 1 })).toBe('success')
    expect(skewTone({ offset: 31, uncertainty: 0.1 })).toBe('danger')
    expect(skewTone(null)).toBe('unknown')
  })

  it('reads the NTP state the node reports', () => {
    expect(ntpState({ ntp: { source: 'chrony', synchronized: true } })).toBe('synced')
    expect(ntpState({ ntp: { source: 'timedatectl', synchronized: false } })).toBe('unsynced')
    expect(ntpState({ ntp: { ntp_enabled: false, synchronized: null } })).toBe('unsynced')
    expect(ntpState({ ntp: { source: null, synchronized: null } })).toBe('unknown')
    expect(ntpState({})).toBe('unknown')
  })
})
