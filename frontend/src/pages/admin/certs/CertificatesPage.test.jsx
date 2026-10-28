// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import CertificatesPage from './CertificatesPage'
import { api } from '../../../services/api'

vi.mock('../../../services/api', () => {
  const api = {
    certs: { overview: vi.fn(), renew: vi.fn() },
    install: { haTlsPlan: vi.fn() },
    plans: { apply: vi.fn(), get: vi.fn(), rollback: vi.fn() },
    jobs: { get: vi.fn() },
  }
  return { api, default: api }
})

vi.mock('../../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

const DAY = 86400000
const iso = (ms) => new Date(ms).toISOString()

// GET /admin/certificates with one node whose Kea HA relationship names a certificate set by hand.
const OVERVIEW = {
  nodes: [
    {
      node_id: 'n1', name: 'ns1', reachable: true, is_self: true, current: null, source: { source: 'self_signed' },
      kea_ha: [
        {
          engine: 'kea4', server: 'server1', role: 'primary', full: true,
          cert: {
            path: '/etc/kea/tls/server1.crt', issuer: 'CN=Pelagos cluster c1', issuer_common_name: 'Pelagos cluster c1',
            san: ['192.0.2.11'], not_before: iso(Date.now() - 700 * DAY), not_after: iso(Date.now() + 10 * DAY), cluster_ca: true,
          },
        },
      ],
    },
  ],
  cluster: null, settings: {}, thresholds: { warning_days: 30, critical_days: 7 }, providers: [], acme_profiles: [], key_types: [],
}

describe('CertificatesPage Kea HA certificates', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.certs.overview.mockResolvedValue(OVERVIEW)
  })

  it('lists the HA certificate with its expiry and plans the renewal of every peer', async () => {
    api.install.haTlsPlan.mockResolvedValue({ id: 'p1', scope: 'security', changes: [], diff: '', summary: 'renew' })
    render(<MemoryRouter><CertificatesPage /></MemoryRouter>)
    const entry = await screen.findByTestId('cert-kea-ha-entry')
    expect(entry.dataset.server).toBe('server1')
    expect(within(entry).getByText('192.0.2.11')).toBeInTheDocument()
    expect(within(entry).getByText('cluster CA')).toBeInTheDocument()
    expect(entry.querySelector('[data-level]').dataset.level).toBe('warning')
    fireEvent.click(screen.getByTestId('cert-kea-ha-renew'))
    await waitFor(() => expect(api.install.haTlsPlan).toHaveBeenCalled())
  })
})
