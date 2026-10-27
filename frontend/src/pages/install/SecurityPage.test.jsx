// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SecurityPage from './SecurityPage'
import { api } from '../../services/api'
import { isDualKey, isRemediable, remediableIds } from './findings'

vi.mock('../../services/api', () => {
  const api = {
    install: { security: vi.fn(), securityPlan: vi.fn() },
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

describe('SecurityPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.install.security.mockResolvedValue({ findings: FINDINGS })
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
