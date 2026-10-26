// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { StrictMode } from 'react'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { subjectLink, jobResult, exceptionItems } from './lib'

const N1 = '01JB0000000000000000NS1AAA'
const ALERTS = [
  { id: 'A1', kind: 'ptr_mismatch', severity: 'warning', state: 'open', node_id: null, engine: null, subject: 'ip:192.0.2.106', title: 'PTR of 192.0.2.106 names another host', details: { ip: '192.0.2.106', exception_keys: ['192.0.2.106|pc7.example.lan.'] }, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' },
  { id: 'A2', kind: 'pool_full', severity: 'critical', state: 'open', node_id: N1, engine: 'kea4', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', title: 'Pool is full', details: {}, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' },
]

const calls = { list: vi.fn(), ack: vi.fn(), run: vi.fn(), addException: vi.fn() }
const notify = { showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showPrompt: vi.fn() }
let canWrite = true

vi.mock('../../services/api', () => {
  const api = {
    alerts: {
      summary: async () => ({ open: 2, acked: 1, by_severity: { critical: 1, warning: 1, info: 0 }, by_kind: {} }),
      list: async (q) => {
        calls.list(q)
        return { items: ALERTS, page: 1, per_page: 50, total: 2, meta: {} }
      },
      ack: async (id, comment) => {
        calls.ack(id, comment)
        return { ...ALERTS[0], state: 'acked' }
      },
      addException: async (body) => {
        calls.addException(body)
        return { id: 'E1', ...body }
      },
      runConsistency: async () => {
        calls.run()
        return { job_id: 'J1' }
      },
    },
    jobs: { get: async () => ({ id: 'J1', state: 'done', steps: [{ name: 'consistency', state: 'done' }, { name: 'result', output: { found: 3 } }] }) },
    nodes: { list: async () => ({ items: [{ peer: { id: N1, name: 'ns1' }, is_self: true }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => p !== 'write:alerts' || canWrite }) }))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => notify }))

const { default: AlertsPage } = await import('./AlertsPage')

const renderPage = (url = '/alerts') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <AlertsPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  canWrite = true
  for (const fn of [...Object.values(calls), ...Object.values(notify)]) fn.mockReset()
})

describe('AlertsPage', () => {
  it('lists open alerts by default with their counts', async () => {
    renderPage()
    const table = await screen.findByTestId('alerts-table')
    await waitFor(() => expect(within(table).getByText('Pool is full')).toBeInTheDocument())
    expect(calls.list).toHaveBeenCalledWith(expect.objectContaining({ state: 'open' }))
    expect(screen.getByText('Acknowledged', { selector: '*' })).toBeInTheDocument()
  })

  it('lists every state when the state filter is cleared', async () => {
    renderPage('/alerts?state=')
    await screen.findByText('Pool is full')
    expect(calls.list.mock.calls.at(-1)[0].state).toBeUndefined()
  })

  it('acknowledges with the comment typed', async () => {
    notify.showPrompt.mockResolvedValue('known, fixing')
    renderPage()
    await screen.findByText('Pool is full')
    fireEvent.click(screen.getAllByTestId('alert-row-ack')[0])
    await waitFor(() => expect(calls.ack).toHaveBeenCalledWith('A1', 'known, fixing'))
    expect(notify.showSuccess).toHaveBeenCalled()
  })

  it('shows the detail with a link to the host', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('PTR of 192.0.2.106 names another host'))
    const detail = await screen.findByTestId('alert-detail')
    expect(within(detail).getByTestId('alert-open-subject')).toHaveTextContent('Open the host')
  })

  it('ignores the objects of an inconsistency with a mandatory comment', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('PTR of 192.0.2.106 names another host'))
    fireEvent.click(await screen.findByTestId('alert-ignore'))
    const dialog = await screen.findByTestId('ignore-dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Ignore' }))
    expect(await within(dialog).findByText('Say why the object is left as it is')).toBeInTheDocument()
    expect(calls.addException).not.toHaveBeenCalled()
    fireEvent.change(screen.getByTestId('ignore-comment'), { target: { value: 'printer has no reverse on purpose' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Ignore' }))
    await waitFor(() =>
      expect(calls.addException).toHaveBeenCalledWith({ kind: 'ptr_mismatch', key: '192.0.2.106|pc7.example.lan.', comment: 'printer has no reverse on purpose', summary: 'PTR of 192.0.2.106 names another host' }),
    )
    expect(notify.showSuccess).toHaveBeenCalledWith('Exception recorded')
  })

  it('offers no ignore for alerts that are not inconsistencies', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('Pool is full'))
    await screen.findByTestId('alert-detail')
    expect(screen.queryByTestId('alert-ignore')).toBeNull()
  })

  it('runs a consistency pass and reports what it found', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('alerts-consistency'))
    await waitFor(() => expect(notify.showSuccess).toHaveBeenCalledWith(expect.stringContaining('3')))
    expect(calls.run).toHaveBeenCalled()
  })

  it('reports the consistency pass under StrictMode', async () => {
    render(
      <StrictMode>
        <MemoryRouter initialEntries={['/alerts']}>
          <AlertsPage />
        </MemoryRouter>
      </StrictMode>,
    )
    const button = await screen.findByTestId('alerts-consistency')
    fireEvent.click(button)
    await waitFor(() => expect(notify.showSuccess).toHaveBeenCalledWith(expect.stringContaining('3')))
    await waitFor(() => expect(screen.getByTestId('alerts-consistency')).not.toBeDisabled())
  })

  it('hides write actions without write:alerts', async () => {
    canWrite = false
    renderPage()
    await screen.findByText('Pool is full')
    expect(screen.queryByTestId('alerts-consistency')).toBeNull()
    expect(screen.queryByTestId('alert-row-ack')).toBeNull()
  })
})

describe('alert subjects', () => {
  it('leads to the host, zone or screen the alert is about', () => {
    expect(subjectLink({ subject: 'ip:2001:db8::1' }).to).toBe('/hosts?q=2001%3Adb8%3A%3A1')
    expect(subjectLink({ subject: 'name:pc1.example.lan./A' }).to).toBe('/hosts?q=pc1.example.lan')
    expect(subjectLink({ subject: 'zone:example.lan.@internal' }).to).toBe('/dns/zones/example.lan?view=internal')
    expect(subjectLink({ subject: 'kea6:subnet:1:pool:2001:db8::/64' }).to).toBe('/dhcp/v6/subnets')
    expect(subjectLink({ subject: 'peer:01JB' }).to).toBe('/nodes')
    expect(subjectLink({ subject: 'engine:bind' })).toBeNull()
  })

  it('lists the exception keys of an inconsistency', () => {
    const alert = { kind: 'ptr_mismatch', details: { exception_keys: ['192.0.2.60|a.example.lan.', '192.0.2.60|b.example.lan.'] } }
    expect(exceptionItems(alert, 'title')).toEqual([
      { kind: 'ptr_mismatch', key: '192.0.2.60|a.example.lan.', summary: '192.0.2.60|a.example.lan.' },
      { kind: 'ptr_mismatch', key: '192.0.2.60|b.example.lan.', summary: '192.0.2.60|b.example.lan.' },
    ])
    expect(exceptionItems({ kind: 'pool_full', details: { exception_keys: ['x'] } })).toEqual([])
    expect(exceptionItems({ kind: 'duplicate_ip', details: {} })).toEqual([])
  })

  it('reads the result step of a job', () => {
    expect(jobResult({ steps: [{ name: 'result', output: { found: 2 } }] })).toEqual({ found: 2 })
    expect(jobResult({ steps: [] })).toBeNull()
  })
})
