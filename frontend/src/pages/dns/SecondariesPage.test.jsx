// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const N1 = '01JB0000000000000000NS1AAA'
const zone = (name) => ({ name, kind: 'secondary', view: '_default', primaries: ['192.0.2.53'] })
const status = (expires) => ({ [N1]: { zone: 'x', node_id: N1, kind: 'secondary', serial: 7, next_refresh: '2026-10-24T12:00:00Z', expires, error: null } })

let zones = []
const zoneDetail = vi.fn()
vi.mock('../../services/api', () => {
  const api = {
    dns: {
      zones: async () => ({ items: zones }),
      zone: async (name) => {
        zoneDetail(name)
        return { zone: zone(name), status: status('2026-11-01T00:00:00Z') }
      },
    },
    nodes: { list: async () => ({ items: [{ peer: { id: N1, name: 'ns1' }, is_self: true, status: 'online' }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))

const { default: SecondariesPage } = await import('./SecondariesPage')

const renderPage = () =>
  render(
    <MemoryRouter>
      <SecondariesPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  zoneDetail.mockReset()
})

describe('SecondariesPage', () => {
  it('uses the bulk zone status of GET /dns/zones', async () => {
    zones = [{ zone: zone('partner.example.'), serials: { [N1]: 7 }, divergent: false, status: status('2026-12-01T00:00:00Z') }]
    renderPage()
    expect(await screen.findByText('partner.example.')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByTestId('secondaries-table')).toHaveTextContent('2026'))
    expect(zoneDetail).not.toHaveBeenCalled()
  })

  it('reads each zone when the list carries no status', async () => {
    zones = [{ zone: zone('upstream.example.'), serials: { [N1]: 7 }, divergent: false }]
    renderPage()
    expect(await screen.findByText('upstream.example.')).toBeInTheDocument()
    await waitFor(() => expect(zoneDetail).toHaveBeenCalledWith('upstream.example.'))
  })
})
