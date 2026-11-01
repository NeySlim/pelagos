// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import NodesPage from './NodesPage'

const mocks = vi.hoisted(() => ({
  api: { nodes: { list: vi.fn(), replication: vi.fn(), sync: vi.fn(), remove: vi.fn() }, dhcp: { ha: vi.fn() } },
  admin: true,
  mobile: false,
}))

vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => (p === 'admin:nodes' ? mocks.admin : true) }) }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ modules: { dhcpv6: false } }) }))
vi.mock('../../contexts/MobileContext', () => ({ useMobile: () => ({ isMobile: mocks.mobile }) }))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../hooks/useWebSocket', () => ({ useWsTopic: () => {} }))
vi.mock('../../hooks/usePoll', () => ({ usePoll: () => {} }))
vi.mock('../../hooks/useClusterSignals', () => ({ useFallbackMs: (ms) => ms }))

const node = (id, name, site, self = false) => ({
  peer: { id, name: `${name}.example.lan`, url: `https://${name}.example.lan:8444`, web_url: null, modules: { bind: true }, cert_fingerprint: 'aa', ...(site ? { site } : {}) },
  is_self: self, status: 'online', version: '0.4.0', config_version: 1, audit_count: 1, last_seen: new Date().toISOString(), clock: null,
})
let items

function renderPage() {
  mocks.api.nodes.list.mockImplementation(async () => ({ items }))
  mocks.api.nodes.replication.mockResolvedValue({ state: 'ready', peers: [] })
  mocks.api.dhcp.ha.mockResolvedValue({ items: [] })
  return render(<MemoryRouter><NodesPage /></MemoryRouter>)
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.admin = true
  mocks.mobile = false
  items = [node('N1', 'ns1', 'dc1', true), node('N2', 'ns2', 'dc1'), node('N3', 'ns3', 'dc2')]
})

describe('NodesPage sites', () => {
  it('groups the table by site once two sites exist', async () => {
    renderPage()
    const groups = await screen.findAllByTestId('nodes-site')
    expect(groups.map((g) => g.dataset.site)).toEqual(['dc1', 'dc2'])
    expect(within(groups[0]).getAllByTestId('data-table-row')).toHaveLength(2)
    expect(screen.queryByRole('columnheader', { name: 'Site' })).toBeNull()
  })

  it('shows a Site column, no groups, with a single site', async () => {
    items = [node('N1', 'ns1', 'dc1', true), node('N2', 'ns2', 'dc1')]
    renderPage()
    expect(await screen.findByRole('columnheader', { name: /Site/ })).toBeInTheDocument()
    expect(screen.queryByTestId('nodes-site')).toBeNull()
  })

  it('shows neither without any site', async () => {
    items = [node('N1', 'ns1', null, true), node('N2', 'ns2', null)]
    renderPage()
    await screen.findAllByTestId('data-table-row')
    expect(screen.queryByRole('columnheader', { name: /Site/ })).toBeNull()
    expect(screen.queryByTestId('nodes-site')).toBeNull()
  })

  it('says why a non-admin cannot enroll', async () => {
    mocks.admin = false
    renderPage()
    expect(await screen.findByTestId('read-only-note')).toHaveTextContent('admin:nodes')
  })
})

describe('NodesPage on a phone', () => {
  it('keeps Sync and Remove on the card of another node, for an admin only', async () => {
    mocks.mobile = true
    renderPage()
    const cards = await screen.findAllByTestId('data-table-card')
    expect(cards).toHaveLength(3)
    // The local node has neither; the others have both.
    expect(within(cards[0]).queryByTestId('node-sync')).toBeNull()
    const sync = within(cards[1]).getByTestId('node-sync')
    expect(sync).toHaveAttribute('title', 'Forces a replication pass with this node')
    expect(within(cards[1]).getByTestId('node-remove')).toBeInTheDocument()
    mocks.api.nodes.sync.mockResolvedValue({ audit_added: 0 })
    fireEvent.click(sync)
    await waitFor(() => expect(mocks.api.nodes.sync).toHaveBeenCalledWith('N2'))
  })

  it('offers no node action to a non-admin', async () => {
    mocks.mobile = true
    mocks.admin = false
    renderPage()
    await screen.findAllByTestId('data-table-card')
    expect(screen.queryByTestId('node-sync')).toBeNull()
    expect(screen.queryByTestId('node-remove')).toBeNull()
  })
})
