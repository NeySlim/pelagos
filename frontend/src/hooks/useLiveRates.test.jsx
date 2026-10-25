// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { resetLiveRates, useLiveRates } from './useLiveRates'

const counters = (res) => ({ total: res.total, parts: {} })

describe('useLiveRates', () => {
  beforeEach(() => resetLiveRates())

  it('sends one request per key while one is in flight', async () => {
    let release
    const load = vi.fn(() => new Promise((resolve) => (release = resolve)))
    const target = { key: 'dns:a', kind: 'dns', node: 'a', load, counters }
    renderHook(() => useLiveRates([target]))
    renderHook(() => useLiveRates([target]))
    await act(async () => {})
    expect(load).toHaveBeenCalledTimes(1)
    await act(async () => release({ total: 1 }))
  })

  it('forgets the series and drops answers requested before a reset', async () => {
    let release
    const load = vi.fn(() => new Promise((resolve) => (release = resolve)))
    const target = { key: 'dns:b', kind: 'dns', node: 'b', load, counters }
    const { result, rerender } = renderHook(() => useLiveRates([target]))
    await act(async () => {})
    resetLiveRates()
    await act(async () => release({ total: 5, collected_at: '2026-10-24T10:00:00Z' }))
    rerender()
    expect(result.current['dns:b'].last).toBeNull()
    expect(sessionStorage.getItem('pelagos-live-rates')).toBeNull()
  })
})
