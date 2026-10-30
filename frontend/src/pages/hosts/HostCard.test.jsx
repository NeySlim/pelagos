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
    ipv6: { hosts: vi.fn(), plan: vi.fn(), reverseZonePlan: vi.fn() },
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
    boot_file_name: null, user_context: { pelagos: { notes: 'Desk 7', owner: 'it' } }, raw: {}, ...overrides,
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
  mocks.api.ipv6.hosts.mockResolvedValue({ items: [], total: 0, page: 1, per_page: 10, meta: {} })
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
    await waitFor(() => expect(mocks.api.dhcp.leaseDeletePlan).toHaveBeenCalledWith('v4', '192.0.2.106', NS1))
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

  it('sends the actions of a DHCPv6 host to the v6 family', async () => {
    const DUID = '00:03:00:01:02:00:5e:00:00:08'
    const v6Lease = lease({ family: 'v6', ip_address: '2001:db8::108', hw_address: null, duid: DUID, iaid: 8, lease_type: 'IA_NA', subnet_id: 10 })
    mocks.api.hosts.get.mockResolvedValue(host({ ips: ['2001:db8::108'], lease: v6Lease, reservation: null, records: [], alerts: [] }))
    mocks.api.dhcp.leaseDeletePlan.mockResolvedValue(plan())
    renderCard()
    fireEvent.click(await screen.findByTestId('host-delete-lease'))
    await waitFor(() => expect(mocks.api.dhcp.leaseDeletePlan).toHaveBeenCalledWith('v6', '2001:db8::108', NS1))
    fireEvent.click(within(await screen.findByTestId('plan-preview')).getByText('Cancel'))
    await waitFor(() => expect(screen.queryByTestId('plan-preview')).not.toBeInTheDocument())

    mocks.api.dhcp.reservationPlan.mockResolvedValue(plan({ scope: 'dhcp.reservation', requires_confirmation: false }))
    fireEvent.click(screen.getByTestId('host-reserve'))
    await waitFor(() => expect(mocks.api.dhcp.reservationPlan).toHaveBeenCalled())
    const [family, change] = mocks.api.dhcp.reservationPlan.mock.calls[0]
    expect(family).toBe('v6')
    expect(change.target).toBe(`subnet6/10/reservations/duid=${DUID}`)
    expect(change.after).toMatchObject({ id_type: 'duid', identifier: DUID, ip_address: null, ip_addresses: ['2001:db8::108'] })
    fireEvent.click(within(await screen.findByTestId('plan-preview')).getByText('Cancel'))

    fireEvent.click(screen.getByTestId('host-open-lease'))
    expect(mocks.openDetail).toHaveBeenCalledWith('lease', 'v6:2001:db8::108', expect.objectContaining({ family: 'v6', ip: '2001:db8::108' }))
  })

  it('offers no reservation for a v6 lease without a DUID', async () => {
    const v6Lease = lease({ family: 'v6', ip_address: '2001:db8::109', duid: null })
    mocks.api.hosts.get.mockResolvedValue(host({ ips: ['2001:db8::109'], lease: v6Lease, reservation: null }))
    renderCard()
    expect(await screen.findByTestId('host-reservation')).toHaveTextContent('No reservation')
    expect(screen.queryByTestId('host-reserve')).not.toBeInTheDocument()
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

  it('derives the join facts of an IPv6 host', () => {
    const v6 = host({
      ips: ['2001:db8::1000'],
      lease: lease({ ip_address: '2001:db8::1000', family: 'v6', lease_type: 'IA_NA', duid: '00:03:00:01:02:00:5e:00:00:07' }),
      reservation: reservation({ ip_address: null, ip_addresses: ['2001:db8::1000'] }),
      records: [{ name: 'pc7.example.lan.', rtype: 'AAAA', ttl: 1200, rdata: ['2001:db8::1000'] }],
    })
    expect(hostFacts(v6)).toMatchObject({ hasForward: true, forwardTypes: ['AAAA'], reservationMismatch: false })
    const moved = { ...v6, reservation: reservation({ ip_address: null, ip_addresses: ['2001:db8::99'] }) }
    expect(hostFacts(moved).reservationMismatch).toBe(true)
    // A v4 reservation says nothing about a v6 lease.
    expect(hostFacts({ ...v6, reservation: reservation() }).reservationMismatch).toBe(false)
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

  it('handles IPv6 subnets and ip6.arpa zones', () => {
    const subnets = [{ id: 10, subnet: '2001:db8::/64' }, { id: 11, subnet: '2001:db8:0:1::/64' }, { id: 1, subnet: '192.0.2.0/24' }]
    expect(subnetFor('2001:db8::108', subnets).id).toBe(10)
    expect(subnetFor('2001:db8:0:1::5', subnets).id).toBe(11)
    expect(subnetFor('2001:db8:1::1', subnets)).toBeNull()
    expect(reverseZoneFor('2001:db8::108', ['8.b.d.0.1.0.0.2.ip6.arpa.'])).toBe('8.b.d.0.1.0.0.2.ip6.arpa.')
    expect(reverseZoneFor('2001:db8::108', ['0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.', '8.b.d.0.1.0.0.2.ip6.arpa.'])).toBe('0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
    expect(reverseZoneFor('2001:db9::1', ['8.b.d.0.1.0.0.2.ip6.arpa.'])).toBeNull()
  })
})

describe('HostCard IPv6 part', () => {
  const v6row = {
    host_key: `mac:${MAC}`, name: 'pc7.example.lan.', mac: MAC, mac_random: false, ipv4: ['192.0.2.106'],
    observed: [
      { address: '2001:db8::5eff:fe00:7', class: 'eui64', sources: ['neighbors'], first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-29T00:00:00Z', current: true },
      { address: '2001:db8::a4b9:12c3:5d6e:7f80', class: 'temporary', sources: ['neighbors'], first_seen: '2026-10-20T00:00:00Z', last_seen: '2026-10-21T00:00:00Z', current: false },
    ],
    aaaa: ['2001:db8::99'], ptr: [], ptr_missing: ['2001:db8::99'], stale: ['2001:db8::99'], excepted: false,
    proposal: { address: '2001:db8::5eff:fe00:7', class: 'eui64', name: 'pc7.example.lan.', zone: 'example.lan.', reverse_zone: null },
  }

  it('lists the observed history of the host and its unobserved AAAA', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    mocks.api.ipv6.hosts.mockResolvedValue({ items: [v6row], total: 1, page: 1, per_page: 10, meta: {} })
    renderCard()
    const section = await screen.findByTestId('host-ipv6')
    await waitFor(() => expect(within(section).getAllByTestId('host-ipv6-class').map((b) => b.textContent)).toEqual(['EUI-64', 'temporary']))
    expect(mocks.api.ipv6.hosts).toHaveBeenCalledWith({ host_key: `mac:${MAC}`, per_page: 10 })
    expect(within(section).getAllByTestId('host-ipv6-seen')[0]).toHaveTextContent('node neighbors')
    expect(within(section).getByText('no longer current')).toBeInTheDocument()
    expect(within(section).getByTestId('host-ipv6-unobserved')).toHaveTextContent('2001:db8::99')
    expect(within(section).getByTestId('host-ipv6-stale')).toBeInTheDocument()
    expect(within(section).getByTestId('host-ipv6-proposal')).toHaveTextContent('no reverse zone')
  })

  it('creates the AAAA and PTR of the proposal, or the reverse zone it lacks first', async () => {
    mocks.api.hosts.get.mockResolvedValue(host())
    mocks.api.ipv6.hosts.mockResolvedValue({ items: [v6row], total: 1, page: 1, per_page: 10, meta: {} })
    const err = Object.assign(new Error('no reverse zone'), { status: 409, code: 'precondition_failed', problem: { reverse_zones: [{ prefix: '2001:db8::/64', zone: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.', view: '_default' }] } })
    mocks.api.ipv6.plan.mockRejectedValueOnce(err)
    mocks.api.ipv6.reverseZonePlan.mockResolvedValue(plan({ scope: 'dns.zone', summary: 'add zone' }))
    renderCard()
    fireEvent.click(await screen.findByTestId('host-ipv6-create'))
    const missing = await screen.findByTestId('host-ipv6-missing-zones')
    expect(mocks.api.ipv6.plan).toHaveBeenCalledWith({ items: [{ host_key: `mac:${MAC}`, address: '2001:db8::5eff:fe00:7' }] })
    fireEvent.click(within(missing).getByTestId('ipv6-reverse-create'))
    await waitFor(() => expect(mocks.api.ipv6.reverseZonePlan).toHaveBeenCalledWith({ prefix: '2001:db8::/64' }))
    expect(await screen.findByTestId('plan-summary')).toHaveTextContent('add zone')
  })

  it('says when nothing was observed and hides the plan without write:dns.records', async () => {
    mocks.permissions = new Set(['read:hosts', 'read:dns'])
    mocks.api.hosts.get.mockResolvedValue(host())
    renderCard()
    expect(await screen.findByTestId('host-ipv6-none')).toHaveTextContent('No IPv6 address observed for this host')
  })
})
