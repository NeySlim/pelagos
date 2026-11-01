// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { SKEW_MARGIN_MS, filtersFromParams, formatLeft, ownsPlan, rollbackWindow, toQuery } from './lib'

describe('plans lib', () => {
  it('maps URL params to the query, dropping empty filters', () => {
    const filters = filtersFromParams(new URLSearchParams('state=applied&other=1'))
    expect(filters).toEqual({ state: 'applied', user: '' })
    expect(toQuery(filters)).toEqual({ state: 'applied' })
  })

  it('does not send the author filter without read:audit', () => {
    const filters = { state: 'applied', user: 'alice' }
    expect(toQuery(filters, { canSeeAll: true })).toEqual({ state: 'applied', user: 'alice' })
    expect(toQuery(filters, { canSeeAll: false })).toEqual({ state: 'applied' })
  })

  it('tells open, closed and no rollback window from rollback_until alone', () => {
    const now = Date.parse('2026-11-01T10:00:00Z')
    const applied = { state: 'applied', rollback_until: '2026-11-01T10:05:00Z' }
    expect(rollbackWindow(applied, now)).toEqual({ status: 'open', leftMs: 300000 })
    expect(rollbackWindow(applied, now + 600000).status).toBe('closed')
    expect(rollbackWindow({ state: 'applied', rollback_until: null }, now).status).toBe('none')
    expect(rollbackWindow({ state: 'rolled_back', rollback_until: null }, now).status).toBe('none')
    // An interrupted FAILED plan has a window too.
    expect(rollbackWindow({ state: 'failed', interrupted: true, rollback_until: applied.rollback_until }, now).status).toBe('open')
  })

  it('closes the window a margin before rollback_until, for a slow browser clock', () => {
    const now = Date.parse('2026-11-01T10:00:00Z')
    const until = new Date(now + SKEW_MARGIN_MS - 1000).toISOString()
    expect(rollbackWindow({ rollback_until: until }, now).status).toBe('closed')
  })

  it('lets the creator and admins roll back, not another reader', () => {
    expect(ownsPlan({ created_by: 'alice' }, { username: 'alice' }, false)).toBe(true)
    expect(ownsPlan({ created_by: 'alice' }, { username: 'bob' }, false)).toBe(false)
    expect(ownsPlan({ created_by: 'alice' }, { username: 'bob' }, true)).toBe(true)
    expect(ownsPlan({ created_by: 'alice' }, null, false)).toBe(false)
  })

  it('formats the time left, with translated units', () => {
    expect(formatLeft(9000)).toBe('9s')
    expect(formatLeft(252000)).toBe('4m 12s')
    expect(formatLeft(86340000)).toBe('23h 59m')
    expect(formatLeft(2 * 86400000 + 3 * 3600000)).toBe('2d 3h')
    const fr = { d: 'j', h: 'h', m: 'min', s: 's' }
    expect(formatLeft(2 * 86400000 + 3 * 3600000, (k, n) => `${n} ${fr[k]}`)).toBe('2 j 3 h')
  })
})
