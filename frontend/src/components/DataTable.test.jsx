// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import { DataTable } from './DataTable'
import { UtilizationBar, utilizationLevel } from './UtilizationBar'
import { StatusBadge } from './StatusBadge'
import { DiffView, parseUnifiedDiff } from './DiffView'
import { JsonTree } from './JsonTree'

const columns = [
  { key: 'name', label: 'Name', sortable: true },
  { key: 'ip', label: 'IP', mono: true, sortable: true },
  { key: 'meta.owner', label: 'Owner' },
]
const rows = [
  { id: 1, name: 'pc10', ip: '192.0.2.110', meta: { owner: 'it' } },
  { id: 2, name: 'pc2', ip: '192.0.2.102', meta: { owner: '<b>x</b>' } },
]

describe('DataTable', () => {
  it('loads with a skeleton at the table geometry and unfolds rows inserted later', () => {
    const { rerender } = render(<DataTable columns={columns} rows={[]} loading animateInserts />)
    expect(screen.getByTestId('data-table-loading')).toHaveAttribute('aria-busy', 'true')
    rerender(<DataTable columns={columns} rows={rows} animateInserts />)
    expect(document.querySelectorAll('tr.fx-row')).toHaveLength(0)
    rerender(<DataTable columns={columns} rows={[...rows, { id: 3, name: 'www', ip: '192.0.2.80', meta: {} }]} animateInserts />)
    const inserted = document.querySelectorAll('tr.fx-row')
    expect(inserted).toHaveLength(1)
    expect(inserted[0]).toHaveTextContent('www')
    rerender(<DataTable columns={columns} rows={rows} animateInserts />)
    expect(document.querySelectorAll('tr.fx-row')).toHaveLength(0)
  })

  it('utilization bars scale from the left and mark both thresholds', () => {
    render(<UtilizationBar percent={42} warn={80} full={95} />)
    expect(screen.getByRole('progressbar').style.transform).toBe('scaleX(0.42)')
    expect(document.querySelectorAll('.ui-progress-tick')).toHaveLength(2)
  })
  it('renders rows as text, including nested keys', () => {
    render(<DataTable columns={columns} rows={rows} />)
    const bodyRows = screen.getAllByTestId('data-table-row')
    expect(bodyRows).toHaveLength(2)
    expect(within(bodyRows[1]).getByText('<b>x</b>')).toBeInTheDocument()
  })

  it('sorts locally with natural order', () => {
    render(<DataTable columns={columns} rows={rows} clientSort />)
    fireEvent.click(screen.getByText('Name'))
    expect(screen.getAllByTestId('data-table-row')[0]).toHaveTextContent('pc2')
    fireEvent.click(screen.getByText('Name'))
    expect(screen.getAllByTestId('data-table-row')[0]).toHaveTextContent('pc10')
  })

  it('reports server sorting and row clicks', () => {
    const onSortChange = vi.fn()
    const onRowClick = vi.fn()
    render(<DataTable columns={columns} rows={rows} sort={{ field: 'ip', order: 'asc' }} onSortChange={onSortChange} onRowClick={onRowClick} />)
    fireEvent.click(screen.getByText('IP'))
    expect(onSortChange).toHaveBeenCalledWith({ field: 'ip', order: 'desc' })
    fireEvent.click(screen.getAllByTestId('data-table-row')[0])
    expect(onRowClick).toHaveBeenCalledWith(rows[0])
  })

  it('shows empty, loading and error states', () => {
    const { rerender } = render(<DataTable columns={columns} rows={[]} emptyTitle="No hosts" />)
    expect(screen.getByText('No hosts')).toBeInTheDocument()
    rerender(<DataTable columns={columns} rows={rows} loading />)
    expect(screen.getByTestId('data-table-loading')).toBeInTheDocument()
    const onRetry = vi.fn()
    rerender(<DataTable columns={columns} rows={rows} error={new Error('boom')} onRetry={onRetry} />)
    expect(screen.getByTestId('data-table-error')).toHaveTextContent('boom')
    fireEvent.click(screen.getByText('Retry'))
    expect(onRetry).toHaveBeenCalled()
  })

  it('paginates through the callback', () => {
    const onPageChange = vi.fn()
    render(<DataTable columns={columns} rows={rows} pagination={{ page: 1, perPage: 2, total: 5, onPageChange }} />)
    fireEvent.click(screen.getByRole('button', { name: '2' }))
    expect(onPageChange).toHaveBeenCalledWith(2)
  })
})

describe('small shared components', () => {
  it('UtilizationBar picks its level from the thresholds', () => {
    expect(utilizationLevel(50)).toBe('success')
    expect(utilizationLevel(85)).toBe('warning')
    expect(utilizationLevel(96)).toBe('danger')
    render(<UtilizationBar assigned={17} total={20} />)
    expect(screen.getByTestId('utilization-bar')).toHaveAttribute('data-level', 'warning')
    expect(screen.getByText('17/20')).toBeInTheDocument()
  })

  it('StatusBadge translates known states and keeps unknown ones readable', () => {
    render(
      <>
        <StatusBadge status="hot-standby" />
        <StatusBadge status="some-new_state" />
      </>,
    )
    expect(screen.getByText('Hot standby')).toBeInTheDocument()
    expect(screen.getByText('some new state')).toBeInTheDocument()
  })

  it('DiffView parses and renders a unified diff', () => {
    const diff = '--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old\n+new\n'
    const parsed = parseUnifiedDiff(diff)
    expect(parsed.filter((l) => l.kind === 'add')).toHaveLength(1)
    expect(parsed.filter((l) => l.kind === 'del')).toHaveLength(1)
    render(<DiffView diff={diff} />)
    expect(screen.getByText('+new')).toBeInTheDocument()
  })

  it('DiffView counts ~ differences as changes, not as +0 -0', () => {
    const diff = '--- running\n+++ /etc/kea/kea-dhcp4.conf\n~ /valid-lifetime: 4000 != 3600\n'
    expect(parseUnifiedDiff(diff)[2].kind).toBe('change')
    render(<DiffView diff={diff} />)
    expect(screen.getByText('~1')).toBeInTheDocument()
    expect(screen.queryByText('+0')).toBeNull()
  })

  it('JsonTree renders untrusted strings as text', () => {
    render(<JsonTree data={{ 'user-context': { note: '<img src=x onerror=alert(1)>' } }} expandedDepth={3} />)
    expect(screen.getByText('"<img src=x onerror=alert(1)>"')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
  })
})
