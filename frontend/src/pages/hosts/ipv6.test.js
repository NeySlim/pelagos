// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6 helpers: URL of a filtered view, stale AAAA and the exception targets of a row.
import { describe, it, expect } from 'vitest'
import {
  defaultAddress, exceptionTargets, ipv6Path, missingReverseZones, parsePrefix, prefix64, prefixSwapErrors, reverseZoneName,
  selectableAddresses, staleAaaa, suggestPrefixSwap, unavailableLines, validFilter,
} from './ipv6'

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

  it('offers the host, the proposal and each current address without AAAA for the missing check', () => {
    const r = row({
      observed: [
        { address: '2001:db8::5eff:fe00:5310', class: 'eui64', last_seen: seen(1), current: true },
        { address: '2001:db8::a', class: 'temporary', last_seen: seen(1), current: false },
        // Seen 5 days ago: current for the server (within stable_min_days), not "in the last day".
        { address: '2001:db8::d', class: 'stable', last_seen: seen(24 * 5), current: true },
        { address: '2001:db8:1::5eff:fe00:5310', class: 'eui64', last_seen: seen(24 * 20), current: false },
      ],
      proposal: { address: '2001:db8::5eff:fe00:5310' },
    })
    expect(exceptionTargets(r, NOW).map((x) => `${x.kind} ${x.key}`)).toEqual([
      'ipv6_missing_aaaa mac:02:00:5e:00:53:10',
      'ipv6_missing_aaaa addr:2001:db8::5eff:fe00:5310',
      'ipv6_missing_aaaa addr:2001:db8::d',
    ])
  })

  it('offers nothing for the missing check once a current address has an AAAA', () => {
    const r = row({
      observed: [
        { address: '2001:db8::b', class: 'stable', last_seen: seen(1), current: true },
        { address: '2001:db8::e', class: 'stable', last_seen: seen(1), current: true },
      ],
      aaaa: ['2001:db8::b'],
      proposal: { address: '2001:db8::e' },
    })
    expect(exceptionTargets(r, NOW)).toEqual([])
  })

  it('falls back to a proposable address seen in the last day without the current flag', () => {
    const r = row({ observed: [{ address: '2001:db8::f', class: 'stable', last_seen: seen(2) }, { address: '2001:db8::9', class: 'stable', last_seen: seen(48) }], proposal: { address: '2001:db8::f' } })
    expect(exceptionTargets(r, NOW).map((x) => x.key)).toEqual(['mac:02:00:5e:00:53:10', 'addr:2001:db8::f'])
  })

  it('offers nothing for the missing check without a proposal, nor the addresses already excepted', () => {
    const observed = [
      { address: '2001:db8::1', class: 'stable', last_seen: seen(1), current: true },
      { address: '2001:db8::2', class: 'stable', last_seen: seen(1), current: true },
    ]
    // No A in a forward zone, or every current address excepted by addr: the check never alerts.
    expect(exceptionTargets(row({ observed }), NOW)).toEqual([])
    // 2001:db8::1 comes before the proposal: the server skipped it, so it is excepted already.
    const r = row({ observed, proposal: { address: '2001:db8::2' } })
    expect(exceptionTargets(r, NOW).map((x) => x.key)).toEqual(['mac:02:00:5e:00:53:10', 'addr:2001:db8::2'])
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

  it('parses prefixes, their /64 and reverse zone', () => {
    expect(parsePrefix('2001:DB8::1/64').text).toBe('2001:db8::/64')
    expect(parsePrefix('2001:db8::/129')).toBeNull()
    expect(parsePrefix('2001:db8::g/64')).toBeNull()
    expect(parsePrefix('1:2:3:4:5:6:7:8:9/64')).toBeNull()
    expect(prefix64('2001:db8:0:1:a:b:c:d')).toBe('2001:db8:0:1::/64')
    expect(reverseZoneName('2001:db8:1::/64')).toBe('0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
    expect(reverseZoneName('2001:db8::/58')).toBe('0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
  })

  it('checks a prefix replacement as the route does', () => {
    expect(prefixSwapErrors('2001:db8::/64', '2001:db8:1::/64')).toEqual({})
    expect(prefixSwapErrors('x', '2001:db8:1::/64')).toEqual({ old_prefix: 'format' })
    expect(prefixSwapErrors('2001:db8::/64', '2001:db8:1::/48')).toEqual({ new_prefix: 'sameLength' })
    expect(prefixSwapErrors('2001:db8::/64', '2001:db8::1/64')).toEqual({ new_prefix: 'overlap' })
    expect(prefixSwapErrors('2001:db8::/8', '2001:db8:1::/8')).toEqual({ old_prefix: 'length', new_prefix: 'length' })
  })

  it('suggests the swap a stale AAAA and a current address in another /64 show', () => {
    const moved = row({ stale: ['2001:db8:0:1::5'], observed: [{ address: '2001:db8:0:2::5', class: 'stable', current: true }] })
    expect(suggestPrefixSwap([row(), moved])).toEqual({ old_prefix: '2001:db8:0:1::/64', new_prefix: '2001:db8:0:2::/64' })
    expect(suggestPrefixSwap([row({ stale: ['2001:db8::5'], observed: [{ address: '2001:db8::6', class: 'stable', current: true }] })])).toBeNull()
  })

  it('selects stable and unknown addresses of a named host, never temporary or complete ones', () => {
    const r = row({
      name: 'pc.example.lan.',
      observed: [
        { address: '2001:db8::1', class: 'stable', current: true },
        { address: '2001:db8::2', class: 'temporary', current: false },
        { address: '2001:db8::3', class: 'unknown', current: false },
        { address: '2001:db8::4', class: 'eui64', current: true },
      ],
      aaaa: ['2001:db8::1', '2001:db8::4'], ptr: ['2001:db8::1'],
    })
    expect(selectableAddresses(r)).toEqual(['2001:db8::3', '2001:db8::4'])
    expect(defaultAddress(r)).toBe('2001:db8::4')
    expect(selectableAddresses({ ...r, name: null })).toEqual([])
    expect(defaultAddress(row({ name: 'x.', observed: [{ address: '2001:db8::9', class: 'unknown', current: false }] }))).toBeNull()
  })

  it('reads the reverse zones of a 409 answer only', () => {
    const zones = [{ prefix: '2001:db8:1::/64', zone: 'z.', view: '_default' }]
    expect(missingReverseZones({ status: 409, problem: { reverse_zones: zones } })).toBe(zones)
    expect(missingReverseZones({ status: 400, problem: { reverse_zones: zones } })).toBeNull()
    expect(missingReverseZones({ status: 409, problem: {} })).toBeNull()
  })
})
