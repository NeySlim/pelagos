// SPDX-License-Identifier: Apache-2.0
// IPv6 observation form: the watched prefix list.
import { describe, it, expect } from 'vitest'
import { prefixProblem, splitList } from './ipv6Form'

describe('ipv6Form', () => {
  it('splits a typed list', () => {
    expect(splitList('2001:db8:1::/64\n fd00:1::/48, ')).toEqual(['2001:db8:1::/64', 'fd00:1::/48'])
  })

  it('checks watched prefixes', () => {
    expect(prefixProblem('2001:db8:1::/64')).toBeNull()
    expect(prefixProblem('fd00:1::/48')).toBeNull()
    expect(prefixProblem('2001:db8::')).toBe('format')
    expect(prefixProblem('192.0.2.0/24')).toBe('format')
    expect(prefixProblem('fe80::/10')).toBe('scope')
    expect(prefixProblem('ff02::/16')).toBe('scope')
  })
})
