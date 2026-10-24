// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { isLiteralTitle, titleCaseClass } from './displayCase'

describe('display title case', () => {
  it('keeps identifiers literal', () => {
    for (const t of ['example.lan.', '192.0.2.0/24', '2001:db8::/64', 'tsig_key', 'admin@example.lan']) {
      expect(isLiteralTitle(t), t).toBe(true)
    }
  })
  it('uppercases static route titles', () => {
    expect(titleCaseClass('Zones')).toBe('ui-title-static')
    expect(titleCaseClass('DHCP subnets')).toBe('ui-title-static')
  })
  it('honours an explicit flag and treats non-string titles as literal', () => {
    expect(isLiteralTitle('web01', true)).toBe(true)
    expect(isLiteralTitle('zone.example', false)).toBe(false)
    expect(isLiteralTitle(null)).toBe(true)
  })
})
