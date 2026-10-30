// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6: rows with classes, records and proposal, filters from and to the URL, the
// unavailable sources banner, an exception per host or address with its comment, and the plans:
// AAAA and PTR of the selection, the reverse zone it lacks, the prefix replacement.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { NotificationProvider } from '../../contexts/NotificationContext'
import '../../i18n'

const db = vi.hoisted(() => ({ rows: [], meta: {}, perms: null, calls: [], added: [], plans: [], planError: null }))

vi.mock('../../services/api', () => {
  const api = {
    ipv6: {
      hosts: async (params) => {
        db.calls.push(params)
        return { items: db.rows, total: db.rows.length, page: 1, per_page: 50, meta: db.meta }
      },
      plan: async (body) => {
        db.plans.push(['plan', body])
        if (db.planError) throw db.planError
        return { id: 'P1', summary: 'AAAA and PTR' }
      },
      replacePrefixPlan: async (body) => {
        db.plans.push(['replace', body])
        if (db.planError) throw db.planError
        return { id: 'P2', summary: 'prefix replaced' }
      },
      reverseZonePlan: async (body) => {
        db.plans.push(['zone', body])
        return { id: 'P3', summary: 'zone' }
      },
    },
    alerts: { addException: async (body) => { db.added.push(body); return { id: 'E1', ...body } } },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../components/PlanPreview', () => ({ PlanPreviewModal: ({ plan }) => <div data-testid="plan-preview">{plan.summary}</div> }))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))

const { Ipv6Panel } = await import('./Ipv6Panel')

const printer = {
  host_key: 'mac:02:00:5e:00:53:10', name: 'printer.example.lan.', mac: '02:00:5e:00:53:10', mac_random: false, ipv4: ['192.0.2.10'],
  observed: [
    { address: '2001:db8::5eff:fe00:5310', class: 'eui64', sources: ['neighbors', 'dhcpv6'], first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' },
    { address: '2001:db8::a4b9:12c3:5d6e:7f80', class: 'temporary', sources: ['neighbors'], first_seen: '2026-10-28T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' },
  ],
  aaaa: [], ptr: [], excepted: false,
  proposal: { address: '2001:db8::5eff:fe00:5310', class: 'eui64', name: 'printer.example.lan.', zone: 'example.lan.', reverse_zone: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.' },
}
const nas = {
  host_key: 'mac:02:00:5e:00:53:20', name: 'nas.example.lan.', mac: '02:00:5e:00:53:20', mac_random: false, ipv4: ['192.0.2.20'],
  observed: [
    { address: '2001:db8::c', class: 'stable', sources: ['dhcpv6'], first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' },
    { address: '2001:db8::20', class: 'stable', sources: ['dhcpv6'], first_seen: '2026-09-01T00:00:00Z', last_seen: '2026-10-09T00:00:00Z' },
  ],
  aaaa: ['2001:db8::20', '2001:db8::c'], ptr: ['2001:db8::c'], proposal: null, excepted: true, stale: ['2001:db8::20'],
}
const phone = { host_key: 'mac:06:11:22:33:44:55', name: null, mac: '06:11:22:33:44:55', mac_random: true, ipv4: [], observed: [{ address: '2001:db8::1', class: 'unknown', sources: ['dhcpv6'], first_seen: null, last_seen: null }], aaaa: [], ptr: [], proposal: null, excepted: false }

// An AAAA of the zone nobody observed: no MAC, a PTR to another name counts as missing.
const apex = { host_key: 'name:example.lan.', name: 'example.lan.', mac: null, mac_random: false, ipv4: [], observed: [], aaaa: ['2001:db8::1', '2001:db8::2'], ptr: ['2001:db8::1', '2001:db8::2'], ptr_missing: ['2001:db8::2'], proposal: null, excepted: false }

let location
function Where() {
  location = useLocation()
  return null
}
const renderPanel = (entry = '/hosts?tab=ipv6') =>
  render(
    <NotificationProvider>
      <MemoryRouter initialEntries={[entry]}>
        <Ipv6Panel zoneOptions={[{ value: 'example.lan.', label: 'example.lan.' }]} />
        <Where />
      </MemoryRouter>
    </NotificationProvider>,
  )
const rowOf = (text) => screen.getByText(text).closest('tr')

beforeEach(() => {
  db.rows = [printer, nas, phone]
  db.meta = { unavailable: [] }
  db.perms = null
  db.calls = []
  db.added = []
  db.plans = []
  db.planError = null
})

describe('Ipv6Panel', () => {
  it('shows observed addresses with their class, records, PTR state and proposal', async () => {
    renderPanel()
    await screen.findByText('printer.example.lan.', { selector: '.font-medium' })
    const printerRow = rowOf('02:00:5e:00:53:10')
    expect(within(printerRow).getAllByTestId('ipv6-class').map((b) => b.textContent)).toEqual(['EUI-64', 'temporary'])
    expect(within(printerRow).getByTestId('ipv6-no-aaaa')).toBeInTheDocument()
    expect(within(printerRow).getByTestId('ipv6-proposal')).toHaveTextContent('2001:db8::5eff:fe00:5310')
    const nasRow = rowOf('02:00:5e:00:53:20')
    expect(within(nasRow).getAllByTestId('ipv6-ptr').map((b) => b.dataset.present)).toEqual(['false', 'true'])
    const stale = within(nasRow).getAllByTestId('ipv6-stale')
    expect(stale).toHaveLength(1)
    expect(stale[0].closest('li').dataset.address).toBe('2001:db8::20')
    expect(stale[0].getAttribute('title')).toMatch(/last seen/)
    expect(within(nasRow).getByTestId('ipv6-excepted')).toBeInTheDocument()
    const phoneRow = rowOf('06:11:22:33:44:55')
    expect(within(phoneRow).getByText('unknown host')).toBeInTheDocument()
    expect(within(phoneRow).getByTestId('ipv6-random-mac')).toBeInTheDocument()
    expect(within(phoneRow).queryByTestId('ipv6-except')).toBeNull()
    expect(screen.getByTestId('ipv6-total')).toHaveTextContent('3')
  })

  it('lists a zone AAAA nobody observed with the PTR state of ptr_mismatch', async () => {
    db.rows = [apex]
    renderPanel()
    await screen.findByText('example.lan.', { selector: '.font-medium' })
    const row = screen.getByText('example.lan.', { selector: '.font-medium' }).closest('tr')
    expect(within(row).getByTestId('ipv6-not-observed')).toBeInTheDocument()
    expect(within(row).getAllByTestId('ipv6-ptr').map((b) => b.dataset.present)).toEqual(['true', 'false'])
    expect(within(row).queryByTestId('ipv6-except')).toBeNull()
  })

  it('reads the filter and zone from the URL and writes the chip back', async () => {
    renderPanel('/hosts?tab=ipv6&filter=stale&zone=example.lan.')
    await waitFor(() => expect(db.calls.at(-1)).toMatchObject({ filter: 'stale', zone: 'example.lan.' }))
    expect(screen.getAllByTestId('ipv6-filter').find((c) => c.dataset.value === 'stale')).toHaveAttribute('aria-pressed', 'true')
    fireEvent.click(screen.getAllByTestId('ipv6-filter').find((c) => c.dataset.value === 'missing_aaaa'))
    await waitFor(() => expect(db.calls.at(-1)).toMatchObject({ filter: 'missing_aaaa' }))
    expect(location.search).toContain('tab=ipv6')
    expect(location.search).toContain('filter=missing_aaaa')
    fireEvent.click(screen.getAllByTestId('ipv6-filter').find((c) => c.dataset.value === ''))
    await waitFor(() => expect(db.calls.at(-1).filter).toBeUndefined())
  })

  it('names the nodes and sources that did not answer', async () => {
    db.meta = { unavailable: [{ node_id: 'N2', source: 'neighbors', error: 'timed out' }], errors: { dns: 'zone list unreadable' } }
    renderPanel()
    await waitFor(() => expect(screen.getByTestId('ipv6-unavailable')).toHaveTextContent('ns2 (neighbors: timed out)'))
    expect(screen.getByTestId('ipv6-errors')).toHaveTextContent('dns: zone list unreadable')
  })

  it('adds an exception for one address with a mandatory comment', async () => {
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    fireEvent.click(within(rowOf('02:00:5e:00:53:10')).getByTestId('ipv6-except'))
    const dialog = await screen.findByTestId('ipv6-exception-dialog')
    const targets = within(dialog).getAllByTestId('ipv6-exception-target')
    expect(targets.map((t) => t.dataset.key)).toEqual(['mac:02:00:5e:00:53:10', 'addr:2001:db8::5eff:fe00:5310'])
    fireEvent.click(targets[1])
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add the exception' }))
    expect(await within(dialog).findByText('Say why this is left as it is')).toBeInTheDocument()
    expect(db.added).toEqual([])
    fireEvent.change(within(dialog).getByTestId('ipv6-exception-comment'), { target: { value: 'printer has no DNS name on v6' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Add the exception' }))
    await waitFor(() => expect(db.added).toEqual([{ kind: 'ipv6_missing_aaaa', key: 'addr:2001:db8::5eff:fe00:5310', comment: 'printer has no DNS name on v6', summary: 'printer.example.lan.' }]))
    await waitFor(() => expect(db.calls.length).toBeGreaterThan(1))
  })

  it('offers no exception without write:alerts', async () => {
    db.perms = ['read:hosts']
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    expect(screen.queryAllByTestId('ipv6-except')).toEqual([])
    expect(screen.queryByTestId('ipv6-sources-link')).toBeNull()
  })

  it('builds the AAAA and PTR plan of the selection, never of a temporary address', async () => {
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    const printerRow = rowOf('02:00:5e:00:53:10')
    expect(within(printerRow).getAllByTestId('ipv6-select-address').map((c) => c.closest('li').dataset.address)).toEqual(['2001:db8::5eff:fe00:5310'])
    // The unknown host has no name: nothing to select; the nas has an AAAA without PTR.
    expect(within(rowOf('06:11:22:33:44:55')).getByTestId('ipv6-select-row')).toBeDisabled()
    expect(screen.getByTestId('ipv6-plan-selection')).toBeDisabled()
    fireEvent.click(within(printerRow).getByTestId('ipv6-select-row'))
    fireEvent.click(within(rowOf('02:00:5e:00:53:20')).getAllByTestId('ipv6-select-address')[0])
    expect(screen.getByTestId('ipv6-plan-selection')).toHaveTextContent('(2)')
    fireEvent.click(screen.getByTestId('ipv6-plan-selection'))
    await screen.findByTestId('plan-preview')
    expect(db.plans).toEqual([['plan', { items: [
      { host_key: 'mac:02:00:5e:00:53:10', address: '2001:db8::5eff:fe00:5310' },
      { host_key: 'mac:02:00:5e:00:53:20', address: '2001:db8::20' },
    ] }]])
  })

  it('offers the missing reverse zone a selection needs', async () => {
    db.planError = Object.assign(new Error('no reverse zone'), { status: 409, code: 'precondition_failed', problem: { reverse_zones: [{ prefix: '2001:db8:1::/64', zone: '0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.', view: '_default' }] } })
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    fireEvent.click(within(rowOf('02:00:5e:00:53:10')).getByTestId('ipv6-select-row'))
    fireEvent.click(screen.getByTestId('ipv6-plan-selection'))
    const dialog = await screen.findByTestId('ipv6-reverse-dialog')
    expect(dialog).toHaveTextContent('0.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
    fireEvent.click(within(dialog).getByTestId('ipv6-reverse-create'))
    await screen.findByTestId('plan-preview')
    expect(db.plans.at(-1)).toEqual(['zone', { prefix: '2001:db8:1::/64' }])
  })

  it('opens the zone of the reverse alert link', async () => {
    renderPanel('/hosts?tab=ipv6&reverse=2001:db8:2::/64')
    const dialog = await screen.findByTestId('ipv6-reverse-dialog')
    expect(dialog).toHaveTextContent('0.0.0.0.2.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.')
  })

  it('checks and builds a prefix replacement', async () => {
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    fireEvent.click(screen.getByTestId('ipv6-replace-prefix'))
    const dialog = await screen.findByTestId('ipv6-replace-dialog')
    fireEvent.change(within(dialog).getByTestId('ipv6-replace-old'), { target: { value: '2001:db8::/64' } })
    fireEvent.change(within(dialog).getByTestId('ipv6-replace-new'), { target: { value: '2001:db8:1::/56' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Build the plan' }))
    expect(await within(dialog).findByText('Both prefixes must have the same length')).toBeInTheDocument()
    expect(db.plans).toEqual([])
    fireEvent.change(within(dialog).getByTestId('ipv6-replace-new'), { target: { value: '2001:db8:1::/64' } })
    fireEvent.change(within(dialog).getByTestId('ipv6-replace-zones'), { target: { value: 'example.lan.' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Build the plan' }))
    await screen.findByTestId('plan-preview')
    expect(db.plans).toEqual([['replace', { old_prefix: '2001:db8::/64', new_prefix: '2001:db8:1::/64', zones: ['example.lan.'] }]])
  })

  it('offers no plan without write:dns.records', async () => {
    db.perms = ['read:hosts']
    renderPanel()
    await screen.findByText('02:00:5e:00:53:10')
    expect(screen.queryByTestId('ipv6-actions')).toBeNull()
    expect(screen.queryAllByTestId('ipv6-select-row')).toEqual([])
  })
})
