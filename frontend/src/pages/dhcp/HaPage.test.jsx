// SPDX-License-Identifier: Apache-2.0
// The HA page of a relationship of more than two servers: every server with its role and
// state (one no Pelagos node runs included), backups drawn as such, the relationship form.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const db = vi.hoisted(() => ({ ha: [], relationships: [], nodes: [] }))
const setupPlan = vi.hoisted(() => vi.fn())

vi.mock('../../hooks/useWebSocket', () => ({
  useWebSocket: () => ({ isConnected: true }),
  useWsTopic: () => {},
}))
vi.mock('../../services/api', () => {
  const api = {
    dhcp: {
      ha: async () => ({ items: db.ha, relationships: db.relationships }),
      servers: async () => ({ items: [] }),
      haTransitions: async () => ({ items: [] }),
      configFile: async () => ({}),
      haSetupPlan: (...args) => setupPlan(...args),
    },
    d2: { configFile: async () => ({}) },
    nodes: { list: async () => ({ items: db.nodes }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))
vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn() }),
}))
vi.mock('../../components/PlanPreview', () => ({ PlanPreviewModal: ({ plan }) => <div data-testid="plan-preview">{plan.summary}</div> }))

const { default: HaPage } = await import('./HaPage')
const { resetNodeNameCache } = await import('./hooks')

const ID = { ns1: 'N1', ns2: 'N2', ns3: 'N3' }
const node = (name) => ({ is_self: name === 'ns1', peer: { id: ID[name], name, url: `https://${name}.example.lan:8444`, modules: { kea4: true, kea6: true } } })
const peers = [
  { name: 'ns1', role: 'primary', url: 'http://ns1.example.lan:8001/' },
  { name: 'ns2', role: 'standby', url: 'http://ns2.example.lan:8001/' },
  { name: 'ns3', role: 'backup', url: 'http://ns3.example.lan:8001/' },
  { name: 'ns9', role: 'backup', url: 'http://192.0.2.99:8001/' },
]
const state = (name, role, st, partner) => ({
  node_id: ID[name], family: 'v4', collected_at: '2026-10-25T10:00:00Z', server_name: name, mode: 'hot-standby', role, state: st,
  scopes: role === 'primary' ? [name] : [], unsent_update_count: 0, enabled: true, peers,
  partner: partner ? { role: partner === 'ns1' ? 'primary' : 'standby', server_name: partner, state: 'hot-standby', in_touch: true, age: 1 } : null,
})
const relServer = (p, extra) => ({ ...p, auto_failover: null, node_id: ID[p.name] || null, node_name: ID[p.name] ? p.name : null, scopes: [], unsent_update_count: 0, partner: null, in_touch: null, collected_at: null, managed: Boolean(ID[p.name]), ...extra })

beforeEach(() => {
  resetNodeNameCache()
  setupPlan.mockReset()
  db.nodes = ['ns1', 'ns2', 'ns3'].map(node)
  db.ha = [state('ns3', 'backup', 'backup'), state('ns1', 'primary', 'hot-standby', 'ns2'), state('ns2', 'standby', 'hot-standby', 'ns1')]
  db.relationships = [
    {
      family: 'v4',
      mode: 'hot-standby',
      servers: [
        relServer(peers[0], { state: 'hot-standby', in_touch: true }),
        relServer(peers[1], { state: 'hot-standby', in_touch: true }),
        relServer(peers[2], { state: 'backup' }),
        relServer(peers[3]),
      ],
      active: ['ns1', 'ns2'],
      backups: ['ns3', 'ns9'],
    },
  ]
})

const renderPage = () => render(<MemoryRouter><HaPage family="v4" /></MemoryRouter>)

describe('HA page with backups', () => {
  it('lists every server of the relationship with its role, the backups drawn as such', async () => {
    renderPage()
    const table = await screen.findByTestId('ha-servers')
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows.map((r) => r.textContent)).toEqual([
      expect.stringMatching(/ns1Primaryns1Hot standbyin touch/),
      expect.stringMatching(/ns2Standbyns2Hot standby/),
      expect.stringMatching(/ns3Backupns3Backupreceives lease updates/),
      expect.stringMatching(/ns9Backupnot a Pelagos node/),
    ])
    const rail = screen.getAllByTestId('ha-rail-server')
    expect(rail.map((r) => r.getAttribute('data-role'))).toEqual(['primary', 'standby', 'backup', 'backup'])
    // Cards follow the roles; a backup has no maintenance, it can be promoted.
    const cards = screen.getAllByTestId('ha-server')
    expect(cards).toHaveLength(3)
    expect(cards[2]).toHaveTextContent('ns3')
    expect(within(cards[2]).getByTestId('ha-backup-note')).toBeInTheDocument()
    expect(within(cards[2]).queryByTestId('ha-maintenance-start')).toBeNull()
    expect(within(cards[0]).getByTestId('ha-maintenance-start')).toBeInTheDocument()
    expect(screen.getByTestId('ha-summary')).toHaveTextContent('2 backup(s) in step')
  })

  it('edits the relationship: a backup added, the plan built for every node', async () => {
    setupPlan.mockResolvedValue({ id: 'P', summary: 'kea4 HA hot-standby on 5 servers', changes: [], target_node_ids: [] })
    renderPage()
    fireEvent.click(await screen.findByTestId('ha-setup'))
    const form = await screen.findByTestId('ha-setup-form')
    expect(within(form).getAllByTestId('ha-setup-server')).toHaveLength(4)
    fireEvent.click(within(form).getByTestId('ha-setup-add'))
    const rows = within(form).getAllByTestId('ha-setup-server')
    expect(rows).toHaveLength(5)
    // An empty row is refused before anything is sent.
    fireEvent.submit(form)
    await waitFor(() => expect(within(form).getAllByText('A name without spaces').length).toBeGreaterThan(0))
    expect(setupPlan).not.toHaveBeenCalled()
    fireEvent.change(within(rows[4]).getByTestId('ha-setup-name'), { target: { value: 'ns10' } })
    fireEvent.change(within(rows[4]).getByTestId('ha-setup-url'), { target: { value: 'http://192.0.2.100:8001/' } })
    fireEvent.submit(form)
    await waitFor(() => expect(setupPlan).toHaveBeenCalled())
    const [family, body] = setupPlan.mock.calls[0]
    expect(family).toBe('v4')
    expect(body.servers.map((s) => `${s.name}:${s.role}:${s.node_id || '-'}`)).toEqual(['ns1:primary:N1', 'ns2:standby:N2', 'ns3:backup:N3', 'ns9:backup:-', 'ns10:backup:-'])
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('5 servers')
  })

  it('promotes a backup into the standby role', async () => {
    db.relationships[0].servers[1] = { ...db.relationships[0].servers[1], state: 'unavailable', in_touch: false }
    renderPage()
    const cards = await screen.findAllByTestId('ha-server')
    fireEvent.click(within(cards[2]).getByTestId('ha-promote'))
    const form = await screen.findByTestId('ha-setup-form')
    const roles = within(form).getAllByTestId('ha-setup-role').map((s) => s.value)
    expect(roles).toEqual(['primary', 'backup', 'standby', 'backup'])
    // A second standby is refused.
    fireEvent.change(within(form).getAllByTestId('ha-setup-role')[1], { target: { value: 'standby' } })
    fireEvent.submit(form)
    expect(await within(form).findByTestId('ha-setup-error')).toHaveTextContent('needs exactly one')
  })
})
