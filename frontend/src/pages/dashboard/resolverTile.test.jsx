// SPDX-License-Identifier: Apache-2.0
// Dashboard resolver tile: worst p95 and SERVFAIL, failing probes, the active fallback.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../../i18n'

const db = vi.hoisted(() => ({ health: null, perms: null }))
vi.mock('../../services/api', () => {
  const api = { resolverHealth: { health: async () => db.health } }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))

const { ResolverTile } = await import('./resolverTile')

const node = (id, p95, servfail, since = null) => ({ node_id: id, error: null, latency_ms: { p95 }, rates: { servfail_clients_percent: servfail }, probes_healthy_since: since })
const health = (extra = {}) => ({ nodes: [node('N1', 120, 0.4), node('N2', 950, 1.25)], unavailable: [], fallback: null, return_ready: false, thresholds: { latency_p95_ms: { warning: 800, critical: 1600 } }, presets: [], ...extra })
const renderTile = () => render(<MemoryRouter><ResolverTile editing={false} /></MemoryRouter>)

beforeEach(() => {
  db.health = health()
  db.perms = null
})

describe('ResolverTile', () => {
  it('shows the worst p95 and SERVFAIL share with the tone of the latency threshold', async () => {
    renderTile()
    expect(await screen.findByTestId('tile-resolver-p95')).toHaveTextContent('950 ms')
    expect(screen.getByTestId('tile-resolver-p95')).toHaveClass('status-warning-text')
    expect(screen.getByTestId('tile-resolver-servfail')).toHaveTextContent('1.3 %')
    expect(screen.getByTestId('tile-resolver-body')).toHaveAttribute('data-tone', 'warning')
    expect(screen.getByTestId('tile-resolver-probes')).toHaveTextContent('Probes healthy, 2/2 nodes measured')
    expect(screen.queryByTestId('tile-resolver-fallback')).toBeNull()
  })

  it('flags failing probes and the active fallback', async () => {
    db.health = health({
      nodes: [node('N1', 120, 0.4, 'unhealthy')],
      unavailable: [{ node_id: 'N2', name: 'ns2', error: 'timeout' }],
      fallback: { forwarders: ['9.9.9.9', '149.112.112.112', '2620:fe::fe'], until: '2026-10-30T10:00:00Z', node_ids: ['N1'], returned: [] },
    })
    renderTile()
    expect(await screen.findByTestId('tile-resolver-fallback')).toHaveTextContent('9.9.9.9, 149.112.112.112')
    expect(screen.getByTestId('tile-resolver-fallback')).toHaveAttribute('href', '/dns/resolver')
    expect(screen.getByTestId('tile-resolver-body')).toHaveAttribute('data-tone', 'danger')
    expect(screen.getByTestId('tile-resolver-probes')).toHaveTextContent('Root or TLD probes failing on 1 node')
    expect(screen.getByTestId('tile-resolver-probes')).toHaveTextContent('1 node silent')
  })

  it('reads nothing without read:dns', () => {
    db.perms = []
    renderTile()
    expect(screen.getByText('Resolver health unavailable')).toBeInTheDocument()
  })
})
