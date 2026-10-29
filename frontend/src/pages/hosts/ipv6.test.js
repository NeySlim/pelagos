// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 helpers: URL of a filtered view, stale AAAA and the exception targets of a row.
import { describe, it, expect } from 'vitest'
import { exceptionTargets, ipv6Path, staleAaaa, unavailableLines, validFilter } from './ipv6'

const row = (extra = {}) => ({ host_key: 'k', mac: '02:00:5e:00:53:10', observed: [], aaaa: [], ptr: [], proposal: null, excepted: false, ...extra })

describe('ipv6 helpers', () => {
  it('builds the tab link with its filter and zone', () => {
    expect(ipv6Path()).toBe('/hosts?tab=ipv6')
    expect(ipv6Path({ filter: 'stale', zone: 'example.lan.' })).toBe('/hosts?tab=ipv6&filter=stale&zone=example.lan.')
    expect(validFilter('random_mac')).toBe('random_mac')
    expect(validFilter('bogus')).toBe('')
  })

  const NOW = Date.parse('2026-10-29T12:00:00Z')
  const seen = (h) => new Date(NOW - h * 3600000).toISOString()

  it('offers the host, the proposal and each recent proposable address without AAAA for the missing check', () => {
    const r = row({
      observed: [
        { address: '2001:db8::5eff:fe00:5310', class: 'eui64', last_seen: seen(1) },
        { address: '2001:db8::a', class: 'temporary', last_seen: seen(1) },
        { address: '2001:db8::b', class: 'stable', last_seen: seen(1) },
        { address: '2001:db8::d', class: 'stable', last_seen: seen(2) },
        { address: '2001:db8:1::5eff:fe00:5310', class: 'eui64', last_seen: seen(24 * 20) },
      ],
      aaaa: ['2001:db8::b'],
      ptr: ['2001:db8::b'],
      proposal: { address: '2001:db8::5eff:fe00:5310' },
    })
    expect(exceptionTargets(r, NOW).map((x) => `${x.kind} ${x.key}`)).toEqual([
      'ipv6_missing_aaaa mac:02:00:5e:00:53:10',
      'ipv6_missing_aaaa addr:2001:db8::5eff:fe00:5310',
      'ipv6_missing_aaaa addr:2001:db8::d',
    ])
  })

  it('takes the stale records from the server, an old sighting included, an alias left out', () => {
    // 2001:db8::20 was last seen 20 days ago (still in the cache); 2001:db8::30 is an alias never seen.
    const r = row({
      excepted: true,
      observed: [
        { address: '2001:db8::c', class: 'stable', last_seen: seen(1) },
        { address: '2001:db8::20', class: 'stable', last_seen: seen(24 * 20) },
      ],
      aaaa: ['2001:db8::20', '2001:db8::30', '2001:db8::c'],
      stale: ['2001:db8::20'],
    })
    expect(staleAaaa(r)).toEqual(['2001:db8::20'])
    expect(exceptionTargets(r, NOW).map((x) => `${x.kind} ${x.key}`)).toEqual(['ipv6_stale_aaaa mac:02:00:5e:00:53:10', 'ipv6_stale_aaaa addr:2001:db8::20'])
    expect(staleAaaa(row())).toEqual([])
  })

  it('has nothing to except on a temporary-only host', () => {
    expect(exceptionTargets(row({ observed: [{ address: '2001:db8::a', class: 'temporary' }] }))).toEqual([])
  })

  it('names the sources that did not answer', () => {
    expect(unavailableLines([{ node_id: 'N2', source: 'neighbors', error: 'timed out' }], (id) => (id === 'N2' ? 'ns2' : id))).toEqual(['ns2 (neighbors: timed out)'])
  })
})
