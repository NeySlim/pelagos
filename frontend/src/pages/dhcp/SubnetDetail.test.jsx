// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { SubnetDetail } from './SubnetDetail'

const mocks = vi.hoisted(() => ({ api: { dhcp: { subnet: vi.fn(), utilization: vi.fn() } } }))
vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

beforeEach(() => {
  vi.clearAllMocks()
  mocks.api.dhcp.subnet.mockResolvedValue({
    id: 3, subnet: '192.0.2.0/24', family: 'v4', options: [], client_classes: [], relay: [], ddns: {},
    pools: [{ pool: '192.0.2.10 - 192.0.2.50', client_classes: [], options: [] }],
    valid_lifetime: 3600, min_valid_lifetime: 600, max_valid_lifetime: 7200, user_context: { pelagos: { notes: 'lab' } },
  })
  mocks.api.dhcp.utilization.mockResolvedValue({
    items: [{ subnet_id: 3, pool: '192.0.2.10 - 192.0.2.50', assigned: 4, total: 41, percent: 10, declined: 2 }],
  })
})

describe('SubnetDetail', () => {
  it('links a pool with declined leases to the filtered leases', async () => {
    render(<MemoryRouter><SubnetDetail family="v4" id={3} /></MemoryRouter>)
    const link = await screen.findByTestId('pool-declined')
    expect(link).toHaveAttribute('href', '/dhcp/v4/leases?subnet_id=3&state=declined')
  })

  it('shows the lifetimes and keeps the notes folded', async () => {
    render(<MemoryRouter><SubnetDetail family="v4" id={3} /></MemoryRouter>)
    expect(await screen.findByText('10m')).toBeInTheDocument()
    expect(screen.getByText('2h')).toBeInTheDocument()
    expect(screen.getByTestId('subnet-notes')).not.toHaveAttribute('open')
  })
})
