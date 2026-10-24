// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { DEFAULT_LAYOUT } from './layout'

const calls = { saveLayout: vi.fn() }
const N1 = '01JB0000000000000000NS1AAA'
const N2 = '01JB0000000000000000NS2BBB'
const node = (id, name, self, status = 'online') => ({ peer: { id, name }, is_self: self, status, version: '0.1.0', config_version: 42, audit_count: 10, last_seen: new Date().toISOString(), error: null })

const SUMMARY = {
  nodes: [node(N1, 'ns1', true), node(N2, 'ns2', false, 'offline')],
  ha: [
    { node_id: N1, family: 'v4', server_name: 'ns1', mode: 'hot-standby', role: 'primary', state: 'hot-standby', unsent_update_count: 0, partner: { state: 'hot-standby', in_touch: true }, enabled: true },
    { node_id: N2, family: 'v4', server_name: 'ns2', mode: 'hot-standby', role: 'standby', state: 'partner-down', unsent_update_count: 3, partner: { state: 'unavailable', in_touch: false }, enabled: true },
  ],
  pools: [
    { node_id: N1, engine: 'kea4', subnet_id: 1, subnet: '192.0.2.0/24', pool: '192.0.2.100 - 192.0.2.199', total: 100, assigned: 20, percent: 20 },
    { node_id: N1, engine: 'kea4', subnet_id: 2, subnet: '198.51.100.0/24', pool: '198.51.100.10 - 198.51.100.19', total: 10, assigned: 9, percent: 90 },
  ],
  zones: [
    { zone: 'example.lan.', view: '_default', serials: { [N1]: 5, [N2]: 5 }, divergent: false },
    { zone: 'lab.example.lan.', view: '_default', serials: { [N1]: 7, [N2]: 6 }, divergent: true },
  ],
  d2: [{ node_id: N2, totals: { 'update-sent': 100, 'update-success': 96, 'update-error': 2, 'update-timeout': 2, 'ncr-error': 0 }, per_key: { 'ddi-admin.': { 'update-sent': 100, 'update-success': 96 } } }],
  alerts: { open: 2, critical: 1, warning: 1, info: 0 },
  engines: {},
}

const ALERTS = [
  { id: 'a1', kind: 'd2_errors', severity: 'warning', state: 'open', title: '4 DNS update errors on ns2', last_seen: '2026-10-24T10:00:00Z' },
  { id: 'a2', kind: 'ha_partner_down', severity: 'critical', state: 'open', title: 'ns1 partner is down', last_seen: '2026-10-24T09:00:00Z' },
]

let savedLayout = []
vi.mock('../../services/api', () => {
  const api = {
    dashboard: {
      summary: async () => SUMMARY,
      getLayout: async () => ({ layout: savedLayout }),
      saveLayout: async (layout) => {
        calls.saveLayout(layout)
        return { layout }
      },
    },
    alerts: { list: async () => ({ items: ALERTS, total: 2, page: 1, per_page: 100 }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))
const showSuccess = vi.fn()
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess, showError: vi.fn() }) }))

const { default: DashboardPage } = await import('./DashboardPage')

const renderPage = () =>
  render(
    <MemoryRouter>
      <DashboardPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  savedLayout = []
  calls.saveLayout.mockReset()
  showSuccess.mockReset()
})

describe('DashboardPage', () => {
  it('renders every tile from the summary', async () => {
    renderPage()
    const nodes = await screen.findByTestId('tile-nodes')
    expect(within(nodes).getByText('1/2 online')).toBeInTheDocument()
    expect(within(nodes).getAllByTestId('tile-node')).toHaveLength(2)

    const ha = screen.getByTestId('tile-ha')
    expect(within(ha).getAllByTestId('tile-ha-row')).toHaveLength(2)
    expect(within(ha).getByText('not in touch')).toBeInTheDocument()

    const zones = screen.getByTestId('tile-zones')
    expect(within(zones).getByText('1 of 2 divergent')).toBeInTheDocument()
    expect(within(zones).getAllByTestId('tile-zone')[0]).toHaveTextContent('lab.example.lan.')

    const pools = screen.getByTestId('tile-pools')
    expect(within(pools).getAllByTestId('tile-pool')[0]).toHaveTextContent('198.51.100.10 - 198.51.100.19')
    expect(within(pools).getByText('1 above threshold')).toBeInTheDocument()

    expect(within(screen.getByTestId('tile-d2')).getByText('4 errors')).toBeInTheDocument()

    const inc = screen.getByTestId('tile-inconsistencies')
    expect(within(inc).getByTestId('tile-alerts-critical')).toHaveTextContent('1')
    await waitFor(() => expect(within(inc).getAllByTestId('tile-alert')[0]).toHaveTextContent('ns1 partner is down'))
  })

  it('saves the layout through PUT /dashboard/layout', async () => {
    savedLayout = [{ i: 'd2', x: 0, y: 0, w: 12, h: 6 }]
    renderPage()
    fireEvent.click(await screen.findByTestId('dashboard-edit'))
    const save = screen.getByTestId('dashboard-save')
    expect(save).toBeDisabled()
    fireEvent.click(screen.getByTestId('dashboard-reset'))
    expect(save).toBeEnabled()
    fireEvent.click(save)
    await waitFor(() => expect(calls.saveLayout).toHaveBeenCalledTimes(1))
    expect(calls.saveLayout.mock.calls[0][0]).toEqual(DEFAULT_LAYOUT)
    await waitFor(() => expect(showSuccess).toHaveBeenCalledWith('Layout saved'))
    expect(screen.getByTestId('dashboard-edit')).toBeInTheDocument()
  })
})
