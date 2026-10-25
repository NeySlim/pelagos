// SPDX-License-Identifier: Apache-2.0
// Live tables and toasts: a removed row folds in place, a changed cell lights once, a page
// change is not an event, entering rows tell their renderers; a toast carries a detail and
// an inline action; serial history and pool latches are built from real samples.
import { describe, it, expect, vi, afterEach } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { DataTable } from './DataTable'
import { NotificationProvider, useNotification } from '../contexts/NotificationContext'
import { mergeSeries, pushSample } from '../pages/dns/serialHistory'
import { poolSeriesQuery, pressureLatches } from '../pages/alerts/lib'
import { latestLease } from '../pages/dashboard/summary'

const columns = [
  { key: 'name', label: 'Name' },
  { key: 'serial', label: 'Serial', render: (r, raw, meta) => `${raw}${meta?.entering ? ' new' : ''}` },
]
const row = (id, serial = 1) => ({ id, name: `n${id}`, serial })

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('DataTable motion', () => {
  it('folds a removed row in place, then drops it', () => {
    vi.useFakeTimers()
    const { rerender } = render(<DataTable columns={columns} rows={[row(1), row(2), row(3)]} animateInserts animateRemovals />)
    rerender(<DataTable columns={columns} rows={[row(1), row(3)]} animateInserts animateRemovals />)
    const leaving = screen.getByTestId('data-table-row-leaving')
    expect(leaving).toHaveTextContent('n2')
    expect(leaving).toHaveAttribute('data-row-phase', 'leave')
    const order = [...document.querySelectorAll('tbody tr')].map((tr) => tr.textContent)
    expect(order[1]).toContain('n2')
    act(() => vi.advanceTimersByTime(400))
    expect(screen.queryByTestId('data-table-row-leaving')).toBeNull()
  })

  it('holds a removed row before it folds when asked', () => {
    vi.useFakeTimers()
    const { rerender } = render(<DataTable columns={columns} rows={[row(1), row(2)]} animateRemovals leaveHoldMs={150} />)
    rerender(<DataTable columns={columns} rows={[row(1)]} animateRemovals leaveHoldMs={150} />)
    expect(screen.getByTestId('data-table-row-leaving').style.getPropertyValue('--fx-leave-hold')).toBe('150ms')
    act(() => vi.advanceTimersByTime(300))
    expect(screen.queryByTestId('data-table-row-leaving')).not.toBeNull()
    act(() => vi.advanceTimersByTime(200))
    expect(screen.queryByTestId('data-table-row-leaving')).toBeNull()
  })

  it('tells renderers which rows enter, and treats a page change as no event', () => {
    const many = (from) => Array.from({ length: 12 }, (_, i) => row(from + i))
    const { rerender } = render(<DataTable columns={columns} rows={[row(1)]} animateInserts animateRemovals />)
    rerender(<DataTable columns={columns} rows={[row(1), row(2)]} animateInserts animateRemovals />)
    expect(screen.getByText('1 new')).toBeInTheDocument()
    rerender(<DataTable columns={columns} rows={many(100)} animateInserts animateRemovals />)
    expect(document.querySelectorAll('tr.fx-row')).toHaveLength(0)
  })

  it('lights a changed cell once per change', () => {
    const { rerender } = render(<DataTable columns={columns} rows={[row(1, 5)]} highlightChanges={['serial']} />)
    const cell = () => screen.getAllByRole('cell')[1]
    expect(cell()).not.toHaveAttribute('data-changed')
    rerender(<DataTable columns={columns} rows={[row(1, 5)]} highlightChanges={['serial']} />)
    expect(cell()).not.toHaveAttribute('data-changed')
    rerender(<DataTable columns={columns} rows={[row(1, 6)]} highlightChanges={['serial']} />)
    expect(cell()).toHaveClass('fx-hl-a')
    rerender(<DataTable columns={columns} rows={[row(1, 7)]} highlightChanges={['serial']} />)
    expect(cell()).toHaveClass('fx-hl-b')
    expect(screen.getAllByRole('cell')[0]).not.toHaveAttribute('data-changed')
  })
})

function Trigger({ onAction }) {
  const { showToast } = useNotification()
  return (
    <button type="button" onClick={() => showToast({ type: 'success', message: 'Plan applied', detail: '1 change in example.lan.', action: { label: 'Roll back plan', onClick: onAction } })}>
      go
    </button>
  )
}

describe('toast action', () => {
  it('shows the detail and runs the inline action, with a duration hairline', async () => {
    const onAction = vi.fn()
    render(
      <NotificationProvider>
        <Trigger onAction={onAction} />
      </NotificationProvider>,
    )
    fireEvent.click(screen.getByText('go'))
    expect(await screen.findByText('1 change in example.lan.')).toBeInTheDocument()
    expect(document.querySelector('.fx-toast-ttl').style.getPropertyValue('--fx-ttl')).toBe('9000ms')
    fireEvent.click(screen.getByTestId('toast-action'))
    expect(onAction).toHaveBeenCalledTimes(1)
  })
})

describe('histories', () => {
  it('keeps serial steps sorted and only where the serial changes', () => {
    const points = []
    expect(pushSample(points, 10, 5)).toBe(true)
    expect(pushSample(points, 20, 5)).toBe(false)
    expect(pushSample(points, 30, 6)).toBe(true)
    expect(pushSample(points, 5, 4)).toBe(true)
    expect(pushSample(points, 40, null)).toBe(false)
    expect(points).toEqual([[5, 4], [10, 5], [30, 6]])
    const entry = { lanes: new Map() }
    expect(mergeSeries(entry, { series: [{ node_id: 'n2', points: [[1, 7, false], [2, 7, false], [3, 8, true]] }] })).toBe(true)
    expect(entry.lanes.get('n2')).toEqual([[1000, 7], [3000, 8]])
  })

  it('latches a pool alert where its use crossed the line, and releases it when resolved', () => {
    expect(poolSeriesQuery({ subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', node_id: 'n1' })).toMatchObject({ engine: 'kea4', subnet_id: '3', pool: '192.0.2.200 - 192.0.2.219' })
    expect(poolSeriesQuery({ subject: 'ip:192.0.2.1' })).toBeNull()
    const t0 = Date.parse('2026-10-25T10:00:00Z')
    const points = [[t0 - 600000, 80], [t0, 100], [t0 + 600000, 85]]
    const open = pressureLatches({ first_seen: new Date(t0).toISOString(), state: 'open', details: { percent: 100 } }, points, 95)
    expect(open).toEqual([{ t: t0 - 600000 + 450000, value: 95, state: 'open' }])
    const resolved = pressureLatches({ first_seen: new Date(t0).toISOString(), state: 'resolved', resolved_at: new Date(t0 + 600000).toISOString() }, points, 95)
    expect(resolved.map((l) => l.state)).toEqual(['held', 'released'])
    expect(resolved[1].value).toBe(85)
  })

  it('finds the latest lease by its last client transaction', () => {
    expect(latestLease([{ ip_address: 'a', cltt: '2026-10-25T10:00:00Z' }, { ip_address: 'b', cltt: '2026-10-25T10:05:00Z' }, { ip_address: 'c' }]).ip_address).toBe('b')
    expect(latestLease([])).toBeNull()
  })
})
