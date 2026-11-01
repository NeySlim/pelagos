// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { NotificationProvider } from '../../contexts/NotificationContext'
import { SubnetForm } from './SubnetForm'

const mocks = vi.hoisted(() => ({ api: { dhcp: { subnetPlan: vi.fn() } } }))
vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))

const subnet = {
  id: 1, subnet: '192.0.2.0/24', family: 'v4', shared_network: null, interface: null, relay: [], client_classes: [],
  pools: [{ pool: '192.0.2.100 - 192.0.2.150', client_classes: [], options: [], user_context: {}, raw: {} }],
  pd_pools: [], options: [{ name: 'routers', data: '192.0.2.1', space: 'dhcp4', raw: {} }],
  valid_lifetime: 3600, min_valid_lifetime: 1800, max_valid_lifetime: 7200, reservations: [], ddns: {}, raw: {}, user_context: {},
}

function renderForm(props = {}) {
  const flow = { build: vi.fn().mockResolvedValue({ id: 'plan' }), building: false }
  render(
    <MemoryRouter>
      <NotificationProvider>
        <SubnetForm family="v4" subnet={subnet} existing={[subnet]} sharedNetworks={[]} onClose={vi.fn()} flow={flow} {...props} />
      </NotificationProvider>
    </MemoryRouter>,
  )
  return flow
}

const preview = () => screen.getByRole('button', { name: 'Preview the plan' })

beforeEach(() => vi.clearAllMocks())

describe('SubnetForm', () => {
  it('disables the preview until something changes', () => {
    renderForm()
    expect(preview()).toBeDisabled()
    fireEvent.change(screen.getByTestId('subnet-valid-lifetime'), { target: { value: '4000' } })
    expect(preview()).toBeEnabled()
    fireEvent.change(screen.getByTestId('subnet-valid-lifetime'), { target: { value: '3600' } })
    expect(preview()).toBeDisabled()
  })

  it('edits the minimum and maximum valid lifetime', async () => {
    const flow = renderForm()
    fireEvent.change(screen.getByTestId('subnet-min-lifetime'), { target: { value: '900' } })
    fireEvent.change(screen.getByTestId('subnet-max-lifetime'), { target: { value: '86400' } })
    fireEvent.click(preview())
    await waitFor(() => expect(flow.build).toHaveBeenCalled())
    await flow.build.mock.calls[0][0]()
    const change = mocks.api.dhcp.subnetPlan.mock.calls[0][1]
    expect(change.after.min_valid_lifetime).toBe(900)
    expect(change.after.max_valid_lifetime).toBe(86400)
    expect(change.after.valid_lifetime).toBe(3600)
  })

  it('refuses a minimum above the default', async () => {
    const flow = renderForm()
    fireEvent.change(screen.getByTestId('subnet-min-lifetime'), { target: { value: '9000' } })
    fireEvent.click(preview())
    expect((await screen.findAllByText(/min <= default <= max/)).length).toBeGreaterThan(0)
    expect(flow.build).not.toHaveBeenCalled()
  })

  it('adds and removes pools one row at a time and validates each', async () => {
    const flow = renderForm()
    expect(screen.getAllByTestId('subnet-pools-row')).toHaveLength(1)
    fireEvent.click(screen.getByTestId('subnet-pools-add'))
    const rows = screen.getAllByTestId('subnet-pools-row')
    expect(rows).toHaveLength(2)
    fireEvent.change(rows[1].querySelector('input'), { target: { value: 'not a pool' } })
    fireEvent.click(preview())
    expect(await screen.findByText(/Not a pool/)).toBeInTheDocument()
    expect(flow.build).not.toHaveBeenCalled()
    fireEvent.change(rows[1].querySelector('input'), { target: { value: '192.0.2.200 - 192.0.2.220' } })
    fireEvent.click(screen.getAllByTestId('subnet-pools-remove')[0])
    expect(screen.getAllByTestId('subnet-pools-row')).toHaveLength(1)
    fireEvent.click(preview())
    await waitFor(() => expect(flow.build).toHaveBeenCalled())
    await flow.build.mock.calls[0][0]()
    const after = mocks.api.dhcp.subnetPlan.mock.calls[0][1].after
    expect(after.pools.map((p) => p.pool)).toEqual(['192.0.2.200 - 192.0.2.220'])
  })

  it('edits options as key and value rows', async () => {
    const flow = renderForm()
    fireEvent.click(screen.getByTestId('subnet-options-add'))
    const rows = screen.getAllByTestId('subnet-options-row')
    const [key, value] = rows[1].querySelectorAll('input')
    fireEvent.change(key, { target: { value: 'domain-name-servers' } })
    fireEvent.change(value, { target: { value: '192.0.2.53' } })
    fireEvent.click(preview())
    await waitFor(() => expect(flow.build).toHaveBeenCalled())
    await flow.build.mock.calls[0][0]()
    const options = mocks.api.dhcp.subnetPlan.mock.calls[0][1].after.options
    expect(options.map((o) => [o.name, o.data])).toEqual([['routers', '192.0.2.1'], ['domain-name-servers', '192.0.2.53']])
  })

  it('explains the greyed ID field', () => {
    renderForm()
    expect(screen.getByTestId('subnet-id')).toBeDisabled()
    expect(screen.getByText('To change the identifier, delete then recreate')).toBeInTheDocument()
  })
})
