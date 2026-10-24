// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { findPreviousBackup, PREVIOUS_PER_PAGE } from './history'

const entry = (id, ts, file = '/etc/bind/named.conf.local', extra = {}) => ({ id, ts, engine: 'bind', node_id: 'ns1', files: [file], ...extra })

describe('findPreviousBackup', () => {
  it('picks the newest older backup of the same file', async () => {
    const items = [entry('c', '2026-10-24T12:00:00Z'), entry('x', '2026-10-24T11:00:00Z', '/etc/bind/other.conf'), entry('b', '2026-10-24T10:00:00Z'), entry('a', '2026-10-24T09:00:00Z')]
    const fetchPage = vi.fn(async () => ({ items, total: items.length }))
    expect((await findPreviousBackup(items[0], fetchPage)).id).toBe('b')
    expect(fetchPage).toHaveBeenCalledWith(expect.objectContaining({ engine: 'bind', node_id: 'ns1', page: 1 }))
    expect(await findPreviousBackup(items[3], fetchPage)).toBe(null)
  })

  it('looks beyond the first page', async () => {
    const newer = Array.from({ length: PREVIOUS_PER_PAGE }, (_, i) => entry(`n${i}`, `2026-10-24T12:${String(i % 60).padStart(2, '0')}:00Z`, '/etc/bind/other.conf'))
    const item = entry('cur', '2026-10-24T10:00:00Z')
    const pages = { 1: newer, 2: [item, entry('prev', '2026-10-23T10:00:00Z')] }
    const fetchPage = vi.fn(async (q) => ({ items: pages[q.page] || [], total: PREVIOUS_PER_PAGE + 2 }))
    expect((await findPreviousBackup(item, fetchPage)).id).toBe('prev')
    expect(fetchPage).toHaveBeenCalledTimes(2)
  })
})
