// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { filtersFromParams, toQuery, FILTER_KEYS } from './filters'

describe('audit filters', () => {
  it('reads every filter from the URL, empty when absent', () => {
    const f = filtersFromParams(new URLSearchParams('user=alice&result=error'))
    expect(Object.keys(f)).toEqual(FILTER_KEYS)
    expect(f.user).toBe('alice')
    expect(f.target).toBe('')
  })

  it('builds the GET /audit query with RFC 3339 times', () => {
    const local = '2026-10-24T10:00'
    const q = toQuery({ user: 'alice', action: 'dns.', target: '', from: local, to: 'not a date' })
    expect(q).toEqual({ user: 'alice', action: 'dns.', from: new Date(local).toISOString() })
  })
})
