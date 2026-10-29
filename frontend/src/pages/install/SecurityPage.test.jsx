// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SecurityPage from './SecurityPage'
import { api } from '../../services/api'
import { isDualKey, isRemediable, remediableIds, planSelection, driftAction } from './findings'
import { guardBadge, parsePeers } from './guard'

vi.mock('../../services/api', () => {
  const api = {
    install: { security: vi.fn(), securityPlan: vi.fn(), haGuard: vi.fn(), haGuardPlan: vi.fn(), permissions: vi.fn() },
    alerts: { addException: vi.fn(), revokeException: vi.fn() },
    plans: { apply: vi.fn(), get: vi.fn(), rollback: vi.fn() },
    jobs: { get: vi.fn() },
  }
  return { api, default: api }
})

vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

// Shapes of installer.security_audit.Finding.to_dict() as GET /install/security sends them.
const finding = (engine, kind, subject, extra = {}) => ({
  id: `${engine}:${kind}:${subject}`, kind, severity: 'critical', engine, subject,
  description: `${kind} on ${subject}`, proposal: 'fix it', risk: 'none', remediable: true,
  description_message: null, proposal_message: null, risk_message: null, ...extra,
})
const FINDINGS = [
  finding('bind', 'weak_shared_kea_key', 'ddns-legacy'),
  finding('kea', 'weak_shared_kea_key', 'kea-ddns'),
  finding('bind', 'weak_rndc_key', 'rndc-key'),
  finding('kea', 'kea_http_socket_plain', 'kea4:192.0.2.1', { remediable: false }),
]

const renderPage = () => render(<MemoryRouter><SecurityPage /></MemoryRouter>)
const row = (id) => screen.getAllByTestId('security-finding').find((el) => el.dataset.finding === id)

describe('findings helpers', () => {
  it('treat the shared Kea key as a dual-key switch on either engine', () => {
    expect(FINDINGS.map(isDualKey)).toEqual([true, true, false, false])
  })

  it('keep findings without automatic remediation out of a plan', () => {
    expect(isRemediable({})).toBe(true)
    expect(remediableIds(FINDINGS)).toEqual(FINDINGS.slice(0, 3).map((f) => `|${f.id}`))
  })
})

describe('drift and guard helpers', () => {
  const drift = finding('kea', 'managed_drift', 'ha_guard', { actions: ['adopt', 'restore'], differences: ['x'] })

  it('send the chosen drift action with the id, restore by default', () => {
    expect(driftAction(drift)).toBe('restore')
    expect(planSelection([drift, FINDINGS[2]], ['|kea:managed_drift:ha_guard', '|bind:weak_rndc_key:rndc-key'], { '|kea:managed_drift:ha_guard': 'adopt' }))
      .toEqual(['kea:managed_drift:ha_guard#adopt', 'bind:weak_rndc_key:rndc-key'])
    expect(driftAction({ ...drift, actions: ['adopt'] }, {})).toBe('adopt')
  })

  it('read the guard state and the address list', () => {
    expect(guardBadge({ legacy: {} }).key).toBe('legacy')
    expect(guardBadge({ managed: {}, differences: ['d'] }).key).toBe('drift')
    expect(guardBadge({ managed: {}, differences: [] }).key).toBe('managed')
    expect(guardBadge({}).key).toBe('absent')
    expect(parsePeers('192.0.2.12\n192.0.2.13, 192.0.2.12  2001:db8::12')).toEqual(['192.0.2.12', '192.0.2.13', '2001:db8::12'])
  })
})

describe('SecurityPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.install.haGuard.mockResolvedValue({ node_id: 'n1', nft: true, listeners: [], managed: null, legacy: null, loaded: null, differences: [] })
    api.install.security.mockResolvedValue({ findings: FINDINGS })
    api.install.permissions.mockResolvedValue({ node_id: 'n1', available: true, checks: [] })
  })

  it('shows the dual-key steps for the shared Kea key from BIND and from D2', async () => {
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('security-finding')).toHaveLength(4))
    expect(within(row('bind:weak_shared_kea_key:ddns-legacy')).getByTestId('security-dual-key')).toBeInTheDocument()
    expect(within(row('kea:weak_shared_kea_key:kea-ddns')).getByTestId('security-dual-key')).toBeInTheDocument()
    expect(within(row('bind:weak_rndc_key:rndc-key')).queryByTestId('security-dual-key')).toBeNull()
    expect(within(row('bind:weak_shared_kea_key:ddns-legacy')).getByText('Weak Kea DDNS key')).toBeInTheDocument()
  })

  it('marks manual findings and leaves them out of select all', async () => {
    api.install.securityPlan.mockResolvedValue(null)
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('security-finding')).toHaveLength(4))
    const manual = row('kea:kea_http_socket_plain:kea4:192.0.2.1')
    expect(within(manual).getByTestId('security-manual')).toHaveTextContent('Manual fix')
    expect(within(manual).getByTestId('security-manual-action')).toHaveTextContent('fix it')
    expect(manual.querySelector('input')).toBeDisabled()
    fireEvent.click(screen.getByTestId('security-select-all'))
    expect(screen.getByTestId('security-select-all')).toBeChecked()
    fireEvent.click(screen.getByTestId('security-build'))
    await waitFor(() => expect(api.install.securityPlan).toHaveBeenCalledWith(FINDINGS.slice(0, 3).map((f) => f.id)))
  })

  it('plans findings picked on two nodes and keeps an excepted one apart', async () => {
    const on = (f, node, extra = {}) => ({ ...f, node_id: node, node_name: node, exception_keys: [`${node}|${f.id}`, f.id], exception: null, ...extra })
    const rndc = FINDINGS[2]
    api.install.security.mockResolvedValue({
      findings: [
        on(rndc, 'ns1'),
        on(rndc, 'ns2'),
        on(FINDINGS[0], 'ns2', { exception: { id: 'x1', key: `ns2|${FINDINGS[0].id}`, comment: 'by design', created_by: 'admin', created_at: '2026-10-27T10:00:00Z' } }),
      ],
      nodes: [{ id: 'ns1', ok: true }, { id: 'ns2', ok: true }],
      node_choices: [{ id: 'ns1', name: 'ns1' }, { id: 'ns2', name: 'ns2' }],
      local_node_id: 'ns1',
    })
    api.install.securityPlan.mockResolvedValue(null)
    api.alerts.revokeException.mockResolvedValue(null)
    renderPage()
    await waitFor(() => expect(screen.getAllByTestId('security-finding')).toHaveLength(2))
    expect(screen.getByTestId('security-excepted')).toHaveTextContent('by design')
    fireEvent.click(screen.getByTestId('security-select-all'))
    fireEvent.click(screen.getByTestId('security-build'))
    await waitFor(() => expect(api.install.securityPlan).toHaveBeenCalledWith({ ns1: [rndc.id], ns2: [rndc.id] }))
    fireEvent.click(screen.getByTestId('security-unexcept'))
    await waitFor(() => expect(api.alerts.revokeException).toHaveBeenCalledWith('x1'))
  })
})

describe('HA guard card', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.install.security.mockResolvedValue({ findings: [], nodes: [], node_choices: [], local_node_id: 'n1' })
    api.install.securityPlan.mockResolvedValue({ id: 'p1', scope: 'security', changes: [], state: 'validated' })
    api.install.haGuardPlan.mockResolvedValue({ id: 'p2', scope: 'security', changes: [], state: 'validated' })
  })
  const listeners = [{ engine: 'kea4', server: 'ns1', address: '192.0.2.11:8001', port: 8001, peers: ['192.0.2.12'] }]

  it('adopts a guard set up by hand on the node it belongs to', async () => {
    api.install.haGuard.mockResolvedValue({
      node_id: 'n1', nft: true, listeners, managed: null, loaded: null, differences: [], suggested_peers: ['192.0.2.12'],
      legacy: { table: 'inet kea_ha_guard', unit: '/etc/systemd/system/kea-ha-guard.service', files: [], peers: ['192.0.2.12'], ports: [8001] },
    })
    renderPage()
    expect(await screen.findByTestId('ha-guard-state')).toHaveTextContent(/hand/i)
    fireEvent.click(screen.getByTestId('ha-guard-adopt'))
    await waitFor(() => expect(api.install.securityPlan).toHaveBeenCalledWith({ n1: ['kea:kea_ha_guard_unmanaged:kea_ha_guard'] }))
  })

  it('plans the edited address list', async () => {
    api.install.haGuard.mockResolvedValue({
      node_id: 'n1', nft: true, listeners, legacy: null, loaded: { peers: ['192.0.2.12'], ports: [8001] }, differences: [],
      suggested_peers: ['192.0.2.12'],
      managed: { table: 'inet pelagos_kea_ha_guard', unit: 'pelagos-kea-ha-guard.service', peers: ['192.0.2.12'], ports: [8001] },
    })
    renderPage()
    const box = await screen.findByTestId('ha-guard-peers')
    fireEvent.change(box, { target: { value: '192.0.2.12\n192.0.2.13' } })
    fireEvent.click(screen.getByTestId('ha-guard-plan'))
    await waitFor(() => expect(api.install.haGuardPlan).toHaveBeenCalledWith(undefined, ['192.0.2.12', '192.0.2.13']))
  })
})
