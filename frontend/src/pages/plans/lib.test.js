// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from 'vitest'
import { filtersFromParams, formatLeft, rollbackWindow, toQuery } from './lib'

describe('plans lib', () => {
  it('maps URL params to the query, dropping empty filters', () => {
    const filters = filtersFromParams(new URLSearchParams('state=applied&other=1'))
    expect(filters).toEqual({ state: 'applied', user: '' })
    expect(toQuery(filters)).toEqual({ state: 'applied' })
  })

  it('tells open, closed and no rollback window', () => {
    const now = Date.parse('2026-11-01T10:00:00Z')
    const applied = { state: 'applied', rollback_until: '2026-11-01T10:05:00Z' }
    expect(rollbackWindow(applied, now)).toEqual({ status: 'open', leftMs: 300000 })
    expect(rollbackWindow(applied, now + 600000).status).toBe('closed')
    expect(rollbackWindow({ state: 'applied', rollback_until: null }, now).status).toBe('none')
    expect(rollbackWindow({ state: 'rolled_back', rollback_until: applied.rollback_until }, now).status).toBe('none')
  })

  it('formats the time left', () => {
    expect(formatLeft(9000)).toBe('9s')
    expect(formatLeft(252000)).toBe('4m 12s')
    expect(formatLeft(86340000)).toBe('23h 59m')
    expect(formatLeft(2 * 86400000 + 3 * 3600000)).toBe('2d 3h')
  })
})
