// SPDX-License-Identifier: Apache-2.0
// DDNS > Failover: zone states and blockers with the handover link, outage and stale banners,
// D2 lists, and the prepare, promote and replay plans sent with the right bodies.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../../i18n'

const db = vi.hoisted(() => ({ res: null, alerts: [], perms: null }))
const calls = vi.hoisted(() => ({ prepare: vi.fn(), failover: vi.fn(), switchover: vi.fn(), replay: vi.fn() }))

vi.mock('../../hooks/useWebSocket', () => ({ useWebSocket: () => ({ isConnected: true }), useWsTopic: () => {} }))
vi.mock('../../services/api', () => {
  const plan = (summary) => async () => ({ id: 'P1', summary, changes: [], validations: [] })
  const api = {
    ddnsFailover: {
      resilience: async () => db.res,
      preparePlan: (...a) => { calls.prepare(...a); return plan('prepare')() },
      failoverPlan: (...a) => { calls.failover(...a); return plan('failover')() },
      switchoverPlan: (...a) => { calls.switchover(...a); return plan('switchover')() },
      replayPlan: (...a) => { calls.replay(...a); return plan('replay')() },
    },
    alerts: { list: async ({ kind }) => ({ items: db.alerts.filter((a) => a.kind === kind) }) },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))
vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn() }),
}))
vi.mock('../../components/PlanPreview', () => ({ PlanPreviewModal: ({ plan }) => <div data-testid="plan-preview">{plan.summary}</div> }))

const { DdnsFailoverPanel } = await import('./DdnsFailoverPanel')
const { resetNodeNameCache } = await import('./hooks')

const msg = (key, params = {}) => ({ key, params })
const zone = (name, extra = {}) => ({ zone: name, view: '_default', primary_node_id: 'N1', epoch: 1, since: '2026-10-01T00:00:00Z', prepared_at: '2026-10-01T00:00:00Z', copies: ['N2'], ready: true, blockers: [], stale: [], ...extra })
const base = () => ({
  zones: [
    zone('example.lan.', { epoch: 0, since: null, prepared_at: null, ready: false, blockers: [msg('ddns.blocker.not_managed', { zone: 'example.lan.', node: 'ns1' })] }),
    zone('signed.example.', { epoch: 0, ready: false, prepared_at: null, blockers: [msg('ddns.blocker.signed', { zone: 'signed.example.' })] }),
    zone('corp.example.lan.', { view: 'internal', epoch: 0, ready: false, prepared_at: null, blockers: [msg('ddns.blocker.not_prepared')] }),
    zone('dyn.example.lan.'),
  ],
  d2: [{ node_id: 'N1', domains: [{ direction: 'forward', name: 'dyn.example.lan.', zone: '_default/dyn.example.lan.', servers: [{ address: '192.0.2.11', port: 53, node_id: 'N1', role: 'primary' }, { address: '192.0.2.12', port: 53, node_id: 'N2', role: 'secondary' }] }] }],
  offline: [],
  outage: null,
  replay: { from: null, to: null, source: 'none', candidates: null, notes: [] },
})

const renderPanel = (props = {}) => render(<MemoryRouter><DdnsFailoverPanel {...props} /></MemoryRouter>)
const row = (name) => screen.getAllByText(name, { exact: false }).map((el) => el.closest('tr')).find(Boolean)

beforeEach(() => {
  resetNodeNameCache()
  Object.values(calls).forEach((f) => f.mockReset())
  db.res = base()
  db.alerts = []
  db.perms = null
})

describe('DdnsFailoverPanel', () => {
  it('shows each zone state, its blockers and the handover link of an unmanaged zone', async () => {
    renderPanel()
    await screen.findByTestId('ddns-zones')
    const states = screen.getAllByTestId('ddns-zone-state').map((b) => b.dataset.state)
    expect(states).toEqual(['blocked', 'blocked', 'not_prepared', 'ready'])
    const adopt = screen.getByTestId('ddns-blocker-adopt')
    expect(adopt).toHaveAttribute('href', '/dns/zones/example.lan')
    expect(screen.getAllByTestId('ddns-blocker').map((b) => b.dataset.key)).toContain('ddns.blocker.signed')
    expect(screen.getAllByTestId('ddns-d2-role').map((b) => b.textContent)).toEqual(['primary', 'copy'])
    expect(screen.queryByTestId('ddns-outage-banner')).toBeNull()
  })

  it('prepares one zone or every preparable zone', async () => {
    renderPanel()
    fireEvent.click(await screen.findByTestId('ddns-prepare'))
    await waitFor(() => expect(calls.prepare).toHaveBeenCalledWith(['internal/corp.example.lan.']))
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('prepare')
    expect(screen.getByTestId('ddns-prepare-all')).toHaveTextContent('(1)')
  })

  it('raises the outage banner and promotes the prepared zones with the chosen target', async () => {
    db.res.outage = { since: '2026-10-28T09:50:00Z', zones: ['_default/dyn.example.lan.'] }
    db.alerts = [{ id: 'A1', kind: 'ddns_outage', state: 'open', node_id: 'N1', subject: 'ddns:_default/dyn.example.lan.', details: { cause: 'peer_offline', since: '2026-10-28T09:50:00Z' } }]
    renderPanel({ selectedZone: '_default/dyn.example.lan.' })
    const banner = await screen.findByTestId('ddns-outage-banner')
    await waitFor(() => expect(within(banner).getByTestId('ddns-outage-zone')).toHaveTextContent('ns1 is offline'))
    expect(screen.getByTestId('ddns-row-promote')).toBeInTheDocument()
    fireEvent.click(within(banner).getByTestId('ddns-promote'))
    const form = await screen.findByTestId('ddns-role-form')
    fireEvent.change(within(form).getByTestId('ddns-role-target'), { target: { value: 'N2' } })
    fireEvent.submit(form)
    await waitFor(() => expect(calls.failover).toHaveBeenCalledWith('N2', ['_default/dyn.example.lan.']))
  })

  it('shows a stale primary and whether Pelagos demotes it', async () => {
    db.res.zones[3] = zone('dyn.example.lan.', { primary_node_id: 'N2', epoch: 2, copies: ['N1'], stale: ['N1'] })
    db.alerts = [{ id: 'S1', kind: 'dns_stale_primary', state: 'open', node_id: 'N1', subject: 'ddns:stale:_default/dyn.example.lan.', details: { demotable: false } }]
    renderPanel()
    const banner = await screen.findByTestId('ddns-stale-banner')
    await waitFor(() => expect(banner).toHaveTextContent('ns1 serves it as primary, the role belongs to ns2 (epoch 2)'))
    expect(banner).toHaveTextContent('Same epoch on both sides')
    expect(row('dyn.example.lan.')).toBeTruthy()
  })

  it('hands the role over with a switchover plan', async () => {
    renderPanel()
    fireEvent.click(await screen.findByTestId('ddns-row-switchover'))
    const form = await screen.findByTestId('ddns-role-form')
    fireEvent.submit(form)
    await waitFor(() => expect(calls.switchover).toHaveBeenCalledWith('N2', ['_default/dyn.example.lan.']))
  })

  it('opens the replay with the outage window and sends the chosen body', async () => {
    db.res.replay = { from: '2026-10-28T08:00:00Z', to: '2026-10-28T09:00:00Z', source: 'outage', candidates: 4, notes: ['leases of ns2 not read (kea4): timeout'] }
    renderPanel()
    const card = await screen.findByTestId('ddns-replay')
    expect(card).toHaveTextContent('4')
    expect(within(card).getByTestId('ddns-replay-source')).toHaveTextContent('Last outage')
    expect(within(card).getByTestId('ddns-replay-note')).toHaveTextContent('timeout')
    fireEvent.click(within(card).getByTestId('ddns-replay-open'))
    const form = await screen.findByTestId('ddns-replay-form')
    fireEvent.change(within(form).getByTestId('ddns-replay-family'), { target: { value: 'v4' } })
    fireEvent.submit(form)
    await waitFor(() => expect(calls.replay).toHaveBeenCalledWith({ from: '2026-10-28T08:00:00.000Z', to: '2026-10-28T09:00:00.000Z', family: 'v4' }))
  })

  it('without a known outage counts nothing and opens an empty manual window', async () => {
    renderPanel()
    const card = await screen.findByTestId('ddns-replay')
    expect(within(card).getByTestId('ddns-replay-source')).toHaveTextContent('No outage known')
    expect(within(card).getByTestId('ddns-replay-none')).toHaveTextContent('nothing is counted')
    expect(within(card).queryByText('Leases to replay')).toBeNull()
    const open = within(card).getByTestId('ddns-replay-open')
    expect(open).toHaveTextContent('Manual window')
    fireEvent.click(open)
    const form = await screen.findByTestId('ddns-replay-form')
    expect(within(form).getByTestId('ddns-replay-from')).toHaveValue('')
    fireEvent.submit(form)
    expect(await within(form).findByTestId('ddns-replay-error')).toHaveTextContent('Enter the start')
    expect(calls.replay).not.toHaveBeenCalled()
    fireEvent.change(within(form).getByTestId('ddns-replay-from'), { target: { value: '2026-10-28T08:00' } })
    fireEvent.submit(form)
    await waitFor(() => expect(calls.replay).toHaveBeenCalledWith({ from: new Date('2026-10-28T08:00').toISOString() }))
  })

  it('hides plan actions without write permissions and refuses without read:dns', async () => {
    db.perms = ['read:dhcp', 'read:dns']
    renderPanel()
    await screen.findByTestId('ddns-zones')
    expect(screen.queryByTestId('ddns-prepare-all')).toBeNull()
    expect(screen.queryByTestId('ddns-replay-open')).toBeNull()
    db.perms = ['read:dhcp']
    renderPanel()
    expect(await screen.findByTestId('ddns-failover-denied')).toBeInTheDocument()
  })
})
