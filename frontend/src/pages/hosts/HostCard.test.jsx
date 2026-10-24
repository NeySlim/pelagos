// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, Routes, Route, useLocation } from 'react-router-dom'
import { NotificationProvider } from '../../contexts/NotificationContext'
import { HostCard } from './HostCard'
import { hostFacts } from './lib'
import { reverseZoneFor, subnetFor } from './net'

const mocks = vi.hoisted(() => ({
  api: {
    hosts: { get: vi.fn(), plan: vi.fn() },
    dns: { zones: vi.fn() },
    nodes: { list: vi.fn() },
    dhcp: { leaseDeletePlan: vi.fn(), reservationPlan: vi.fn() },
    plans: { apply: vi.fn(), rollback: vi.fn(), get: vi.fn() },
    jobs: { get: vi.fn() },
  },
  permissions: new Set(['*']),
  openDetail: vi.fn(),
}))

vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))
vi.mock('../../hooks/usePermission', () => ({
  usePermission: () => ({ hasPermission: (p) => mocks.permissions.has('*') || mocks.permissions.has(p) }),
}))
vi.mock('../../components/FloatingDetailWindow', () => ({ useOpenDetail: () => mocks.openDetail }))
vi.mock('../../contexts/MobileContext', () => ({ useMobile: () => ({ isMobile: false }) }))

const NS1 = '01JB0000000000000000NS1AAA'
const MAC = '02:00:5e:00:00:07'

function lease(overrides = {}) {
  return {
    ip_address: '192.0.2.106', subnet_id: 1, family: 'v4', hw_address: MAC, client_id: null, duid: null,
    hostname: 'pc7.example.lan', state: 'default', valid_lft: 3600, cltt: '2026-10-24T10:00:00Z',
    expires_at: '2026-10-24T11:00:00Z', fqdn_fwd: true, fqdn_rev: true, iaid: null, lease_type: null,
    prefix_len: null, preferred_lft: null, pool_id: 0, user_context: {}, node_id: NS1, raw: {}, ...overrides,
  }
}

function reservation(overrides = {}) {
  return {
    subnet_id: 1, id_type: 'hw-address', identifier: MAC, ip_address: '192.0.2.106', ip_addresses: [], prefixes: [],
    hostname: 'pc7.example.lan', client_classes: ['voip'], options: [], next_server: null, server_hostname: null,
    boot_file_name: null, user_context: { 'pelagos:note': 'Desk 7', 'pelagos:owner': 'it' }, raw: {}, ...overrides,
  }
}

function host(overrides = {}) {
  return {
    key: `mac:${MAC}`,
    mac: MAC,
    ips: ['192.0.2.106'],
    hostname: 'pc7.example.lan.',
    lease: lease(),
    reservation: reservation(),
    records: [
      { name: 'pc7.example.lan.', rtype: 'A', ttl: 1200, rdata: ['192.0.2.106'] },
      { name: '106.2.0.192.in-addr.arpa.', rtype: 'PTR', ttl: 1200, rdata: ['workstation7.example.lan.'] },
    ],
    alerts: [
      {
        id: 'ALRT3', kind: 'ptr_mismatch', severity: 'warning', state: 'open', node_id: null, engine: null,
        subject: 'ip:192.0.2.106', title: 'PTR for 192.0.2.106 points to workstation7.example.lan.', details: {},
        first_seen: '2026-10-24T08:00:00Z', last_seen: '2026-10-24T10:00:00Z',
      },
    ],
    ...overrides,
  }
}

function plan(overrides = {}) {
  return {
    id: '01JBPLANHOST00000000000000', created_at: '2026-10-24T10:00:00Z', created_by: 'admin', node_id: NS1,
    scope: 'dhcp.lease', engine: 'kea4', summary: 'delete lease 192.0.2.106', changes: [], diff: '',
    preconditions: [], validations: [], target_node_ids: [NS1], requires_confirmation: true, state: 'validated',
    expires_at: new Date(Date.now() + 600000).toISOString(), error: null, ...overrides,
  }
}

function Where() {
  const location = useLocation()
  return <span data-testid="location">{`${location.pathname}${location.search}`}</span>
}

function renderCard(hostKey = `mac:${MAC}`) {
  return render(
    <MemoryRouter initialEntries={['/hosts']}>
      <NotificationProvider>
        <Routes>
          <Route path="*" element={<><HostCard hostKey={hostKey} /><Where /></>} />
        </Routes>
      </NotificationProvider>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mocks.permissions = new Set(['*'])
  mocks.api.nodes.list.mockResolvedValue({ items: [{ peer: { id: NS1, name: 'ns1' } }] })
  mocks.api.dns.zones.mockResolvedValue({
    items: [{ zone: { name: 'example.lan.' } }, { zone: { name: '2.0.192.in-addr.arpa.' } }],
  })
})

describe('HostCard', () => {
  it('shows the lease, the reservation with its user-context, the records and the inconsistencies', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    renderCard()
    expect(await screen.findByTestId('host-card')).toBeInTheDocument()
    expect(mocks.api.hosts.get).toHaveBeenCalledWith(`mac:${MAC}`)
    expect(screen.getByTestId('host-name')).toHaveTextContent('pc7.example.lan.')
    expect(screen.getByTestId('host-status')).toHaveTextContent('Issues: 1')
    const leaseSection = screen.getByTestId('host-lease')
    expect(leaseSection).toHaveTextContent('192.0.2.106')
    expect(within(leaseSection).getByText('Active')).toBeInTheDocument()
    await waitFor(() => expect(leaseSection).toHaveTextContent('ns1'))
    const res = screen.getByTestId('host-reservation')
    expect(res).toHaveTextContent('hw-address 02:00:5e:00:00:07')
    expect(within(res).getByTestId('user-context')).toHaveTextContent('Desk 7')
    expect(within(res).getByTestId('user-context')).toHaveTextContent('Owner')
    expect(screen.getByTestId('host-records')).toHaveTextContent('workstation7.example.lan.')
    expect(screen.getByTestId('host-ptr-mismatch')).toBeInTheDocument()
    expect(screen.getByTestId('host-alerts')).toHaveTextContent('PTR for 192.0.2.106 points to workstation7.example.lan.')
    // Records exist, so the create-records action is not offered.
    expect(screen.queryByTestId('host-create-records')).not.toBeInTheDocument()
  })

  it('deletes the lease through a plan that asks for confirmation', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    mocks.api.dhcp.leaseDeletePlan.mockResolvedValue(plan())
    renderCard()
    fireEvent.click(await screen.findByTestId('host-delete-lease'))
    await waitFor(() => expect(mocks.api.dhcp.leaseDeletePlan).toHaveBeenCalledWith('v4', '192.0.2.106'))
    expect(await screen.findByTestId('plan-preview')).toBeInTheDocument()
    expect(screen.getByTestId('plan-summary')).toHaveTextContent('delete lease 192.0.2.106')
    expect(screen.getByTestId('plan-apply')).toBeDisabled()
  })

  it('reserves the leased address when there is no reservation', async () => {
    mocks.api.hosts.get.mockResolvedValue(host({ reservation: null }))
    mocks.api.dhcp.reservationPlan.mockResolvedValue(plan({ scope: 'dhcp.reservation', requires_confirmation: false, summary: 'add reservation' }))
    renderCard()
    expect(await screen.findByTestId('host-reservation')).toHaveTextContent('No reservation')
    fireEvent.click(screen.getByTestId('host-reserve'))
    await waitFor(() => expect(mocks.api.dhcp.reservationPlan).toHaveBeenCalled())
    const [family, change] = mocks.api.dhcp.reservationPlan.mock.calls[0]
    expect(family).toBe('v4')
    expect(change.op).toBe('add')
    expect(change.target).toBe(`subnet4/1/reservations/hw-address=${MAC}`)
    expect(change.after).toMatchObject({ subnet_id: 1, id_type: 'hw-address', identifier: MAC, ip_address: '192.0.2.106', hostname: 'pc7.example.lan' })
    expect(await screen.findByTestId('plan-preview')).toBeInTheDocument()
  })

  it('deletes the reservation and opens it in the reservations screen', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    mocks.api.dhcp.reservationPlan.mockResolvedValue(plan({ scope: 'dhcp.reservation' }))
    renderCard()
    fireEvent.click(await screen.findByTestId('host-delete-reservation'))
    await waitFor(() => expect(mocks.api.dhcp.reservationPlan).toHaveBeenCalled())
    const [, change] = mocks.api.dhcp.reservationPlan.mock.calls[0]
    expect(change).toMatchObject({ op: 'delete', after: null, before: { identifier: MAC } })
    fireEvent.click(within(await screen.findByTestId('plan-preview')).getByText('Cancel'))
    await waitFor(() => expect(screen.queryByTestId('plan-preview')).not.toBeInTheDocument())
    fireEvent.click(screen.getByTestId('host-edit-reservation'))
    expect(screen.getByTestId('location')).toHaveTextContent(`/dhcp/v4/reservations?q=${encodeURIComponent(MAC)}`)
  })

  it('creates the missing A and PTR records in the zone that holds the name', async () => {
    mocks.api.hosts.get.mockResolvedValue(host({ records: [], alerts: [], hostname: 'lab1.example.lan.', ips: ['192.0.2.140'], lease: lease({ ip_address: '192.0.2.140', hostname: 'lab1.example.lan' }), reservation: null }))
    mocks.api.hosts.plan.mockResolvedValue(plan({ scope: 'host', requires_confirmation: false, summary: 'create host lab1.example.lan.' }))
    renderCard()
    expect(await screen.findByTestId('host-status')).toHaveTextContent('Consistent')
    await waitFor(() => expect(mocks.api.dns.zones).toHaveBeenCalled())
    fireEvent.click(screen.getByTestId('host-create-records'))
    await waitFor(() => expect(mocks.api.hosts.plan).toHaveBeenCalledWith({ hostname: 'lab1.example.lan.', ip: '192.0.2.140', zone: 'example.lan.', reservation: false }))
    expect(await screen.findByTestId('plan-summary')).toHaveTextContent('create host lab1.example.lan.')
  })

  it('opens the per-node lease window', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    renderCard()
    fireEvent.click(await screen.findByTestId('host-open-lease'))
    expect(mocks.openDetail).toHaveBeenCalledWith('lease', 'v4:192.0.2.106', expect.objectContaining({ family: 'v4', ip: '192.0.2.106' }))
  })

  it('offers no write action to a read-only user', async () => {
    mocks.permissions = new Set(['read:hosts', 'read:dhcp'])
    mocks.api.hosts.get.mockResolvedValue(host({ records: [] }))
    renderCard()
    expect(await screen.findByTestId('host-card')).toBeInTheDocument()
    for (const id of ['host-delete-lease', 'host-delete-reservation', 'host-edit-reservation', 'host-reserve', 'host-create-records']) {
      expect(screen.queryByTestId(id), id).not.toBeInTheDocument()
    }
    expect(screen.getByTestId('host-open-lease')).toBeInTheDocument()
    expect(mocks.api.dns.zones).not.toHaveBeenCalled()
  })

  it('reports a host that cannot be read', async () => {
    mocks.api.hosts.get.mockRejectedValue(Object.assign(new Error('host mac:x not found'), { status: 404, code: 'not_found' }))
    renderCard('mac:x')
    expect(await screen.findByRole('alert')).toHaveTextContent('host mac:x not found')
  })
})

describe('host helpers', () => {
  it('derives the join facts', () => {
    const facts = hostFacts(host())
    expect(facts).toMatchObject({ hasLease: true, hasReservation: true, hasForward: true, hasPtr: true, ptrMismatch: true, reservationMismatch: false, inconsistent: true })
    expect(hostFacts(host({ reservation: reservation({ ip_address: '192.0.2.99' }) })).reservationMismatch).toBe(true)
    expect(hostFacts({ ...host(), records: [], alerts: [] })).toMatchObject({ hasForward: false, ptrMismatch: false, inconsistent: false })
  })

  it('finds the subnet and the reverse zone of an address', () => {
    const subnets = [{ id: 1, subnet: '192.0.2.0/24' }, { id: 2, subnet: '192.0.2.128/26' }]
    expect(subnetFor('192.0.2.140', subnets).id).toBe(2)
    expect(subnetFor('192.0.2.10', subnets).id).toBe(1)
    expect(subnetFor('198.51.100.1', subnets)).toBeNull()
    expect(reverseZoneFor('192.0.2.42', ['2.0.192.in-addr.arpa.'])).toBe('2.0.192.in-addr.arpa.')
    expect(reverseZoneFor('192.0.2.42', ['192.in-addr.arpa.'])).toBe('192.in-addr.arpa.')
    expect(reverseZoneFor('198.51.100.1', ['2.0.192.in-addr.arpa.'])).toBeNull()
  })
})
