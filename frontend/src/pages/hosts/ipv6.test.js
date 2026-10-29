// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 helpers: URL of a filtered view, unobserved AAAA and the exception targets of a row.
import { describe, it, expect } from 'vitest'
import { exceptionTargets, ipv6Path, unavailableLines, unobservedAaaa, validFilter } from './ipv6'

const row = (extra = {}) => ({ host_key: 'k', mac: '02:00:5e:00:53:10', observed: [], aaaa: [], ptr: [], proposal: null, excepted: false, ...extra })

describe('ipv6 helpers', () => {
  it('builds the tab link with its filter and zone', () => {
    expect(ipv6Path()).toBe('/hosts?tab=ipv6')
    expect(ipv6Path({ filter: 'stale', zone: 'example.lan.' })).toBe('/hosts?tab=ipv6&filter=stale&zone=example.lan.')
    expect(validFilter('random_mac')).toBe('random_mac')
    expect(validFilter('bogus')).toBe('')
  })

  it('offers the host and each proposable address without AAAA for the missing check', () => {
    const r = row({
      observed: [
        { address: '2001:db8::5eff:fe00:5310', class: 'eui64' },
        { address: '2001:db8::a', class: 'temporary' },
        { address: '2001:db8::b', class: 'stable' },
      ],
      aaaa: ['2001:db8::b'],
      ptr: ['2001:db8::b'],
      proposal: { address: '2001:db8::5eff:fe00:5310' },
    })
    expect(exceptionTargets(r).map((x) => `${x.kind} ${x.key}`)).toEqual([
      'ipv6_missing_aaaa mac:02:00:5e:00:53:10',
      'ipv6_missing_aaaa addr:2001:db8::5eff:fe00:5310',
    ])
  })

  it('leaves out the host key once excepted and offers the stale records', () => {
    const r = row({ excepted: true, observed: [{ address: '2001:db8::c', class: 'stable' }], aaaa: ['2001:db8::20', '2001:db8::c'] })
    expect(unobservedAaaa(r)).toEqual(['2001:db8::20'])
    expect(exceptionTargets(r).map((x) => `${x.kind} ${x.key}`)).toEqual(['ipv6_stale_aaaa mac:02:00:5e:00:53:10', 'ipv6_stale_aaaa addr:2001:db8::20'])
  })

  it('has nothing to except on a temporary-only host', () => {
    expect(exceptionTargets(row({ observed: [{ address: '2001:db8::a', class: 'temporary' }] }))).toEqual([])
  })

  it('names the sources that did not answer', () => {
    expect(unavailableLines([{ node_id: 'N2', source: 'neighbors', error: 'timed out' }], (id) => (id === 'N2' ? 'ns2' : id))).toEqual(['ns2 (neighbors: timed out)'])
  })
})
