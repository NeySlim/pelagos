// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { NotificationProvider } from '../../contexts/NotificationContext'
import { LeaseDetail } from './LeaseDetail'
import { resetNodeNameCache } from './hooks'

const mocks = vi.hoisted(() => ({
  api: {
    dhcp: { lease: vi.fn(), servers: vi.fn(), leaseDeletePlan: vi.fn() },
    nodes: { list: vi.fn() },
    plans: { apply: vi.fn(), rollback: vi.fn(), get: vi.fn() },
    jobs: { get: vi.fn() },
  },
}))

vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

const NS1 = '01JB0000000000000000NS1AAA'
const NS2 = '01JB0000000000000000NS2AAA'
const IP = '192.0.2.50'

const copy = (node_id) => ({
  ip_address: IP, node_id, state: 'default', hw_address: '02:00:5e:00:00:50', subnet_id: 1, valid_lft: 3600,
  cltt: '2026-10-24T10:00:00Z', expires_at: '2026-10-24T11:00:00Z', fqdn_fwd: false, fqdn_rev: false, user_context: {},
})

const plan = {
  id: '01JBPLANLEASE0000000000000', created_at: '2026-10-24T10:00:00Z', created_by: 'admin', node_id: NS2,
  scope: 'dhcp.lease', engine: 'kea4', summary: `delete lease ${IP}`, changes: [], diff: '', preconditions: [],
  validations: [], target_node_ids: [NS2], requires_confirmation: true, state: 'validated',
  expires_at: new Date(Date.now() + 600000).toISOString(), error: null,
}

function renderDetail() {
  return render(
    <MemoryRouter>
      <NotificationProvider>
        <LeaseDetail family="v4" ip={IP} />
      </NotificationProvider>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  resetNodeNameCache()
  mocks.api.nodes.list.mockResolvedValue({ items: [{ peer: { id: NS1, name: 'ns1' } }, { peer: { id: NS2, name: 'ns2' } }] })
  mocks.api.dhcp.servers.mockResolvedValue({ items: [{ node_id: NS1 }, { node_id: NS2 }] })
  mocks.api.dhcp.leaseDeletePlan.mockResolvedValue(plan)
})

describe('LeaseDetail delete', () => {
  it('deletes a lease only the partner holds on that partner', async () => {
    mocks.api.dhcp.lease.mockResolvedValue({ items: [copy(NS2)] })
    renderDetail()
    fireEvent.click(await screen.findByTestId('lease-delete'))
    await waitFor(() => expect(mocks.api.dhcp.leaseDeletePlan).toHaveBeenCalledWith('v4', IP, NS2))
  })

  it('offers one delete per node when both hold a copy', async () => {
    mocks.api.dhcp.lease.mockResolvedValue({ items: [copy(NS1), copy(NS2)] })
    renderDetail()
    await screen.findByTestId(`lease-delete-${NS1}`)
    expect(screen.queryByTestId('lease-delete')).not.toBeInTheDocument()
    expect(screen.getByTestId('lease-delete-all')).toHaveTextContent('Delete on the 2 servers')
    fireEvent.click(screen.getByTestId(`lease-delete-${NS2}`))
    await waitFor(() => expect(mocks.api.dhcp.leaseDeletePlan).toHaveBeenCalledWith('v4', IP, NS2))
  })
})
