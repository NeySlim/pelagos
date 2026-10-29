// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 observation: settings of the generic sources, poll status per node,
// effective prefixes; save the listed prefixes. No router source any more.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../../../i18n'

const db = vi.hoisted(() => ({ data: null, puts: [] }))

vi.mock('../../../services/api', () => {
  const api = {
    ipv6: {
      settings: async () => db.data,
      update: async (body) => {
        db.puts.push(body)
        if (body.prefixes) db.data = { ...db.data, prefixes: body.prefixes }
        return db.data
      },
    },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn() }),
}))

const { default: Ipv6ObservationPage } = await import('./Ipv6ObservationPage')

const base = () => ({
  prefixes: [],
  effective_prefixes: [{ prefix: '2001:db8::/64', from: 'reverse_zone' }, { prefix: '2001:db8:5::/64', from: 'interface' }],
  settings: { neighbors_enabled: true, poll_seconds: 300, stable_min_days: 8, stale_days: 14, auto_apply_enabled: false },
  status: [
    { source: 'neighbors', source_id: null, node_id: 'N1', last_poll: '2026-10-29T08:00:00Z', error: null, entries: 14 },
    { source: 'neighbors', source_id: null, node_id: 'N2', last_poll: null, error: 'node did not answer', entries: 0 },
    { source: 'dhcpv6', source_id: null, node_id: 'N1', last_poll: '2026-10-29T08:00:00Z', error: null, entries: 6 },
  ],
})

const renderPage = () => render(<MemoryRouter><Ipv6ObservationPage /></MemoryRouter>)

beforeEach(() => {
  db.data = base()
  db.puts = []
})

describe('Ipv6ObservationPage', () => {
  it('shows the generic sources, poll status and effective prefixes', async () => {
    renderPage()
    expect(await screen.findByTestId('ipv6-neighbors')).toHaveTextContent('on')
    expect(screen.getByTestId('ipv6-observation')).toHaveTextContent('Kea DHCPv6 leases')
    expect(screen.getByText('DHCPv6 lease walk (seconds)')).toBeInTheDocument()
    const status = screen.getByTestId('ipv6-status')
    expect(within(status).getAllByTestId('ipv6-status-error').map((e) => e.textContent)).toEqual(['node did not answer'])
    expect(within(status).getByText('DHCPv6 lease')).toBeInTheDocument()
    expect(screen.getAllByTestId('ipv6-effective')[0].querySelectorAll('li')).toHaveLength(2)
    expect(screen.getByText('reverse zone')).toBeInTheDocument()
    expect(screen.queryByTestId('ipv6-sources')).toBeNull()
    expect(screen.queryByTestId('ipv6-source-add')).toBeNull()
  })

  it('shows neighbor tables off when disabled', async () => {
    db.data = { ...base(), settings: { ...base().settings, neighbors_enabled: false } }
    renderPage()
    expect(await screen.findByTestId('ipv6-neighbors')).toHaveTextContent('off')
  })

  it('validates and saves the listed prefixes', async () => {
    renderPage()
    const input = await screen.findByTestId('ipv6-prefixes-input')
    fireEvent.change(input, { target: { value: 'fe80::/10' } })
    expect(await screen.findByText(/Link-local and multicast are never watched/)).toBeInTheDocument()
    expect(screen.getByTestId('ipv6-prefixes-save')).toBeDisabled()
    fireEvent.change(input, { target: { value: '2001:db8:1::/64\nfd00:1::/48' } })
    fireEvent.click(screen.getByTestId('ipv6-prefixes-save'))
    await waitFor(() => expect(db.puts).toEqual([{ prefixes: ['2001:db8:1::/64', 'fd00:1::/48'] }]))
  })
})
