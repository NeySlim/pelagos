// SPDX-License-Identifier: Apache-2.0
// The statistics page says when a server keeps its leases in an SQL database.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const db = vi.hoisted(() => ({ servers: [] }))

vi.mock('../../hooks/useWebSocket', () => ({ useWebSocket: () => ({ isConnected: true }), useWsTopic: () => {} }))
vi.mock('../../hooks/useLiveRates', () => ({ dhcpTarget: () => null, useLiveRates: () => ({}) }))
vi.mock('../../services/api', () => {
  const api = {
    dhcp: { servers: async () => ({ items: db.servers }), stats: async () => ({}), configFile: async () => ({}) },
    d2: { configFile: async () => ({}) },
    alerts: { list: async () => ({ items: [] }) },
    series: { pools: async () => ({ series: [] }) },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn() }),
}))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

const { default: StatsPage } = await import('./StatsPage')
const { resetNodeNameCache } = await import('./hooks')

const server = (node_id, lease_backend) => ({ node_id, capabilities: { version: '3.2.1', lease_backend } })
const renderPage = () => render(<MemoryRouter><StatsPage family="v4" /></MemoryRouter>)

beforeEach(() => resetNodeNameCache())

describe('StatsPage lease database note', () => {
  it('names the nodes whose leases live in MySQL or PostgreSQL', async () => {
    db.servers = [server('N1', 'memfile'), server('N2', 'mysql')]
    renderPage()
    const note = await screen.findByTestId('dhcp-sql-leases-note')
    expect(note).toHaveTextContent('Lease database mysql on ns2')
    expect(note).toHaveTextContent('not supported')
  })

  it('shows no note for memfile', async () => {
    db.servers = [server('N1', 'memfile')]
    renderPage()
    await waitFor(() => expect(screen.getByPlaceholderText('Filter counters...')).toBeInTheDocument())
    expect(screen.queryByTestId('dhcp-sql-leases-note')).toBeNull()
  })
})
