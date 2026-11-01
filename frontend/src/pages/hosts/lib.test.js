// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { presenceChips } from './lib'

const host = (over) => ({ hostname: 'printer.example.lan.', lease: null, reservation: null, records: [], alerts: [], ips: [], ...over })
const lease = { ip_address: '192.0.2.10' }
const a = { rtype: 'A', rdata: ['192.0.2.10'] }
const ptr = { rtype: 'PTR', rdata: ['printer.example.lan.'] }

describe('presenceChips', () => {
  it('lists only what exists', () => {
    expect(presenceChips(host({ lease, records: [a, ptr] })).map((c) => [c.key, Boolean(c.absent)])).toEqual([
      ['lease', false], ['forward', false], ['ptr', false],
    ])
  })

  it('strikes the records a leased, named host should have', () => {
    const chips = presenceChips(host({ lease }))
    expect(chips.filter((c) => c.absent).map((c) => c.label)).toEqual(['A', 'PTR'])
  })

  it('shows nothing absent for a record without a name or a lease', () => {
    expect(presenceChips(host({ hostname: '', lease, records: [] })).filter((c) => c.absent)).toEqual([])
    expect(presenceChips(host({ records: [a] })).map((c) => c.key)).toEqual(['forward'])
  })
})
