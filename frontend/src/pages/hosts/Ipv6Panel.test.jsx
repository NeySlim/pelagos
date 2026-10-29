// SPDX-License-Identifier: Apache-2.0
// Hosts > IPv6: rows with classes, records and proposal, filters from and to the URL, the
// unavailable sources banner, and an exception per host or address with its comment.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import '../../i18n'

const db = vi.hoisted(() => ({ rows: [], meta: {}, perms: null, calls: [], added: [] }))

vi.mock('../../services/api', () => {
  const api = {
    ipv6: {
      hosts: async (params) => {
        db.calls.push(params)
        return { items: db.rows, total: db.rows.length, page: 1, per_page: 50, meta: db.meta }
      },
    },
    alerts: { addException: async (body) => { db.added.push(body); return { id: 'E1', ...body } } },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))

const { Ipv6Panel } = await import('./Ipv6Panel')

const printer = {
  host_key: 'mac:02:00:5e:00:53:10', name: 'printer.example.lan.', mac: '02:00:5e:00:53:10', mac_random: false, ipv4: ['192.0.2.10'],
  observed: [
    { address: '2001:db8::5eff:fe00:5310', class: 'eui64', sources: ['neighbors', 'opnsense'], first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' },
    { address: '2001:db8::a4b9:12c3:5d6e:7f80', class: 'temporary', sources: ['neighbors'], first_seen: '2026-10-28T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' },
  ],
  aaaa: [], ptr: [], excepted: false,
  proposal: { address: '2001:db8::5eff:fe00:5310', class: 'eui64', name: 'printer.example.lan.', zone: 'example.lan.', reverse_zone: '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.' },
}
const nas = {
  host_key: 'mac:02:00:5e:00:53:20', name: 'nas.example.lan.', mac: '02:00:5e:00:53:20', mac_random: false, ipv4: ['192.0.2.20'],
  observed: [{ address: '2001:db8::c', class: 'stable', sources: ['opnsense'], first_seen: '2026-10-01T00:00:00Z', last_seen: '2026-10-29T00:00:00Z' }],
  aaaa: ['2001:db8::20', '2001:db8::c'], ptr: ['2001:db8::c'], proposal: null, excepted: true,
}
const phone = { host_key: 'mac:06:11:22:33:44:55', name: null, mac: '06:11:22:33:44:55', mac_random: true, ipv4: [], observed: [{ address: '2001:db8::1', class: 'unknown', sources: ['opnsense'], first_seen: null, last_seen: null }], aaaa: [], ptr: [], proposal: null, excepted: false }

let location
function Where() {
  location = useLocation()
  return null
}
const renderPanel = (entry = '/hosts?tab=ipv6') =>
  render(
    <MemoryRouter initialEntries={[entry]}>
      <Ipv6Panel zoneOptions={[{ value: 'example.lan.', label: 'example.lan.' }]} />
      <Where />
    </MemoryRouter>,
  )
const rowOf = (text) => screen.getByText(text).closest('tr')

beforeEach(() => {
  db.rows = [printer, nas, phone]
  db.meta = { unavailable: [] }
  db.perms = null
  db.calls = []
  db.added = []
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
    expect(within(nasRow).getAllByTestId('ipv6-not-observed')).toHaveLength(1)
    expect(within(nasRow).getByTestId('ipv6-excepted')).toBeInTheDocument()
    const phoneRow = rowOf('06:11:22:33:44:55')
    expect(within(phoneRow).getByText('unknown host')).toBeInTheDocument()
    expect(within(phoneRow).getByTestId('ipv6-random-mac')).toBeInTheDocument()
    expect(within(phoneRow).queryByTestId('ipv6-except')).toBeNull()
    expect(screen.getByTestId('ipv6-total')).toHaveTextContent('3')
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
})
