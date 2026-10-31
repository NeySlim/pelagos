// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'
import { DataTable } from './DataTable'
import { UtilizationBar, utilizationLevel } from './UtilizationBar'
import { StatusBadge } from './StatusBadge'
import { DiffView, parseUnifiedDiff } from './DiffView'
import { JsonTree } from './JsonTree'

// The phone layout is switched per test; everything else of MobileContext stays real.
let mockMobile = false
vi.mock('../contexts/MobileContext', async (orig) => ({ ...(await orig()), useMobile: () => ({ isMobile: mockMobile }) }))

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

describe('DataTable on a phone', () => {
  const card = {
    title: (row) => row.name,
    subtitle: (row) => row.ip,
    status: (row) => <span>state-{row.id}</span>,
    fields: ['meta.owner', 'ip', 'name', 'zone'],
    primaryAction: (row) => <button type="button">open-{row.id}</button>,
  }
  afterEach(() => { mockMobile = false })

  it('renders cards with at most three fields and the main action visible', () => {
    mockMobile = true
    const withZone = [...columns, { key: 'zone', label: 'Zone' }]
    render(<DataTable columns={withZone} rows={rows.map((r) => ({ ...r, zone: 'example.lan' }))} mobileCard={card} />)
    expect(document.querySelector('table')).toBeNull()
    const cards = screen.getAllByTestId('data-table-card')
    expect(cards).toHaveLength(2)
    expect(within(cards[0]).getAllByText('pc10').length).toBeGreaterThan(0)
    expect(within(cards[0]).getAllByText('192.0.2.110').length).toBeGreaterThan(0)
    expect(within(cards[0]).getByText('state-1')).toBeInTheDocument()
    expect(within(cards[0]).getByRole('button', { name: 'open-1' })).toBeInTheDocument()
    expect(within(cards[0]).getByText('Owner:')).toBeInTheDocument()
    expect(within(cards[0]).getByText('IP:')).toBeInTheDocument()
    expect(within(cards[0]).queryByText('Zone:')).toBeNull()
  })

  it('keeps the table without mobileCard, or on desktop', () => {
    mockMobile = true
    const { rerender } = render(<DataTable columns={columns} rows={rows} />)
    expect(document.querySelector('table')).not.toBeNull()
    mockMobile = false
    rerender(<DataTable columns={columns} rows={rows} mobileCard={card} />)
    expect(document.querySelector('table')).not.toBeNull()
    expect(screen.queryByTestId('data-table-card')).toBeNull()
  })

  it('opens a card with Enter and Space', () => {
    mockMobile = true
    const onRowClick = vi.fn()
    render(<DataTable columns={columns} rows={rows} mobileCard={{ ...card, primaryAction: undefined }} onRowClick={onRowClick} />)
    const first = screen.getAllByRole('button')[0]
    fireEvent.keyDown(first, { key: 'Enter' })
    fireEvent.keyDown(first, { key: ' ' })
    expect(onRowClick).toHaveBeenCalledTimes(2)
    expect(onRowClick).toHaveBeenCalledWith(rows[0])
  })
})

describe('DataTable keyboard', () => {
  it('clickable rows are focus stops that Enter and Space open', () => {
    const onRowClick = vi.fn()
    render(<DataTable columns={columns} rows={rows} onRowClick={onRowClick} selectedKey={2} />)
    const [first, second] = screen.getAllByTestId('data-table-row')
    expect(first).toHaveAttribute('tabindex', '0')
    expect(first).toHaveAttribute('aria-selected', 'false')
    expect(second).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(first, { key: 'Enter' })
    fireEvent.keyDown(second, { key: ' ' })
    fireEvent.keyDown(first, { key: 'a' })
    expect(onRowClick.mock.calls.map((c) => c[0].id)).toEqual([1, 2])
  })

  it('an inner button keeps its own keys', () => {
    const onRowClick = vi.fn()
    const cols = [{ key: 'name', label: 'Name', render: (row) => <button type="button">act-{row.id}</button> }]
    render(<DataTable columns={cols} rows={rows} onRowClick={onRowClick} />)
    fireEvent.keyDown(screen.getByRole('button', { name: 'act-1' }), { key: 'Enter' })
    expect(onRowClick).not.toHaveBeenCalled()
  })

  it('rows without a click handler are not focus stops', () => {
    render(<DataTable columns={columns} rows={rows} />)
    expect(screen.getAllByTestId('data-table-row')[0]).not.toHaveAttribute('tabindex')
  })
})
