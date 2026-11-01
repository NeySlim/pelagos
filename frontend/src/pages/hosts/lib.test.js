// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { presenceChips } from './lib'

const host = (over) => ({ hostname: 'printer.example.lan.', lease: null, reservation: null, records: [], alerts: [], ips: ['192.0.2.10'], ...over })
const lease = { ip_address: '192.0.2.10' }
const a = { rtype: 'A', rdata: ['192.0.2.10'] }
const ptr = { rtype: 'PTR', rdata: ['printer.example.lan.'] }
const alert = (kind, details = {}) => ({ id: kind, kind, severity: 'info', details })

describe('presenceChips', () => {
  it('lists only what exists', () => {
    expect(presenceChips(host({ lease, records: [a, ptr] })).map((c) => [c.key, Boolean(c.absent)])).toEqual([
      ['lease', false], ['forward', false], ['ptr', false],
    ])
  })

  it('strikes nothing for a host the consistency checks do not flag', () => {
    expect(presenceChips(host({ lease })).filter((c) => c.absent)).toEqual([])
  })

  it('strikes the records its alerts expect', () => {
    const chips = presenceChips(host({ lease, alerts: [alert('lease_without_record', { rtype: 'A' }), alert('ptr_mismatch')] }))
    expect(chips.filter((c) => c.absent).map((c) => c.label)).toEqual(['A', 'PTR'])
  })

  it('names AAAA for an IPv6-only host', () => {
    const chips = presenceChips(host({ ips: ['2001:db8::10'], lease, alerts: [alert('ipv6_missing_aaaa')] }))
    expect(chips.find((c) => c.absent).label).toBe('AAAA')
  })

  it('keeps a present record even when an alert exists', () => {
    expect(presenceChips(host({ records: [a, ptr], alerts: [alert('ptr_mismatch')] })).some((c) => c.absent)).toBe(false)
  })
})
