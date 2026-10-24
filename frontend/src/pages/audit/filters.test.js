// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { filtersFromParams, toQuery, toRfc3339, FILTER_KEYS } from './filters'

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

describe('toRfc3339', () => {
  it('drops empty or invalid dates instead of throwing', () => {
    expect(toRfc3339('')).toBe(undefined)
    expect(toRfc3339('garbage')).toBe(undefined)
    expect(toRfc3339('2026-10-24T10:00')).toBe(new Date('2026-10-24T10:00').toISOString())
  })
})
