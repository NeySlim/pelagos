// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { createBody, deleteBody, filterOrphans, orphanKey } from './ptrOrphans'
import { ptrOption } from './records'

const REV = '2.0.192.in-addr.arpa.'
const row = (ip, target, extra = {}) => ({
  ip,
  name: `${ip.split('.').reverse().join('.')}.in-addr.arpa.`,
  target,
  zone: REV,
  view: '_default',
  category: 'orphan',
  excepted: false,
  ...extra,
})

describe('orphan PTR helpers', () => {
  const rows = [
    row('192.0.2.70', 'moved.example.lan.', { fix: 'delete' }),
    row('192.0.2.80', 'printer.example.lan.', { fix: 'create_a', view: 'inside' }),
    row('192.0.2.90', 'mail.example.net.', { category: 'external' }),
    row('192.0.2.91', 'relay.example.net.', { category: 'external', excepted: true }),
  ]

  it('filters by category, ignored rows apart', () => {
    expect(filterOrphans(rows, 'orphan').map((r) => r.ip)).toEqual(['192.0.2.70', '192.0.2.80'])
    expect(filterOrphans(rows, 'external').map((r) => r.ip)).toEqual(['192.0.2.90'])
    expect(filterOrphans(rows, 'excepted').map((r) => r.ip)).toEqual(['192.0.2.91'])
    expect(filterOrphans(rows, 'all')).toHaveLength(4)
  })

  it('builds the plan bodies with the view of non-default rows', () => {
    expect(deleteBody(rows.slice(0, 2))).toEqual({
      delete: [
        { zone: REV, name: '70.2.0.192.in-addr.arpa.', target: 'moved.example.lan.' },
        { zone: REV, name: '80.2.0.192.in-addr.arpa.', target: 'printer.example.lan.', view: 'inside' },
      ],
    })
    expect(createBody([rows[1]])).toEqual({ create: [{ ip: '192.0.2.80', target: 'printer.example.lan.', view: 'inside' }] })
  })

  it('keys a row by view, zone, owner and target', () => {
    expect(orphanKey(rows[0])).toBe('_default|2.0.192.in-addr.arpa.|70.2.0.192.in-addr.arpa.|moved.example.lan.')
    expect(new Set(rows.map(orphanKey)).size).toBe(4)
  })
})

describe('ptrOption', () => {
  const item = (ip, extra = {}) => ({ ip, covered: true, reverse_zone: REV, current: [], conflict: false, points_here: false, ...extra })

  it('is off with the reason when nothing is covered', () => {
    expect(ptrOption({ mode: 'add', coverage: null }).enabled).toBe(false)
    const off = ptrOption({ mode: 'add', coverage: [{ ip: '198.51.100.1', covered: false, reason: 'no_primary' }] })
    expect(off).toMatchObject({ enabled: false, reason: 'no_primary', uncovered: ['198.51.100.1'] })
  })

  it('reports conflicts on new addresses only, and uncovered ones', () => {
    const coverage = [
      item('192.0.2.10', { current: ['old.example.lan.'], conflict: true }),
      item('192.0.2.11', { current: ['other.example.lan.'], conflict: true }),
      { ip: '2001:db8::5', covered: false, reason: 'no_reverse_zone' },
    ]
    const opt = ptrOption({ mode: 'edit', before: { rdata: ['192.0.2.10'] }, coverage })
    expect(opt.enabled).toBe(true)
    expect(opt.conflicts.map((c) => c.ip)).toEqual(['192.0.2.11'])
    expect(opt.uncovered).toEqual(['2001:db8::5'])
    expect(opt.zones).toEqual([REV])
  })

  it('on delete, is on only when a PTR points to the name', () => {
    expect(ptrOption({ mode: 'delete', coverage: [item('192.0.2.10')] })).toMatchObject({ enabled: false, reason: 'noPtrHere' })
    expect(ptrOption({ mode: 'delete', coverage: [item('192.0.2.10', { points_here: true })] }).enabled).toBe(true)
  })
})
