// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'

const db = vi.hoisted(() => ({ alerts: [], calls: [], admin: true, servers: [] }))

vi.mock('../../hooks/useWebSocket', () => ({ useWebSocket: () => ({ isConnected: true }), useWsTopic: () => {} }))
vi.mock('../../services/api', () => {
  const api = {
    alerts: { list: async (params) => { db.calls.push(params); return { items: db.alerts } } },
    dhcp: { servers: async () => ({ items: db.servers }) },
    nodes: { list: async () => ({ items: [{ is_self: true, peer: { id: 'N1', name: 'ns1' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => p !== 'admin:install' || db.admin }) }))

const { KeaSeriesBanner } = await import('./KeaSeriesBanner')
const { obsoleteSeries } = await import('./keaSeries')
const { resetNodeNameCache } = await import('./hooks')

const alert = (id, extra) => ({ id, kind: 'kea_series_obsolete', state: 'open', node_id: 'N1', subject: 'kea:series', details: { series: '2.6', eol: '2026-07-30' }, ...extra })
const show = (path = '/') => render(<MemoryRouter initialEntries={[path]}><KeaSeriesBanner /></MemoryRouter>)

beforeEach(() => {
  resetNodeNameCache()
  db.alerts = []
  db.calls = []
  db.admin = true
  db.servers = []
  try { window.localStorage.clear() } catch { /* no storage */ }
})

describe('KeaSeriesBanner', () => {
  it('names the node, the series and the end of life, and links admins to the analysis', async () => {
    db.alerts = [alert('A1')]
    show()
    const row = await screen.findByTestId('kea-series-banner-row')
    await waitFor(() => expect(row).toHaveTextContent('Kea 2.6 on ns1: ISC no longer maintains this series since 2026-07-30'))
    expect(screen.getByTestId('kea-series-banner-link')).toHaveAttribute('href', '/install/kea-migration')
    expect(db.calls[0]).toEqual({ state: 'open', kind: 'kea_series_obsolete' })
  })

  it('shows no link without admin:install and nothing without an open alert', async () => {
    db.admin = false
    db.alerts = [alert('A1')]
    const { unmount } = show()
    await screen.findByTestId('kea-series-banner')
    expect(screen.queryByTestId('kea-series-banner-link')).toBeNull()
    unmount()
    db.alerts = [alert('A2', { kind: 'ha_terminated' }), alert('A3', { state: 'acked' })]
    show()
    await waitFor(() => expect(db.calls.length).toBe(2))
    expect(screen.queryByTestId('kea-series-banner')).toBeNull()
  })

  it('stays dismissed for the same alerts and comes back for a new one', async () => {
    db.alerts = [alert('A1')]
    const { unmount } = show()
    fireEvent.click(await screen.findByTestId('kea-series-banner-dismiss'))
    expect(screen.queryByTestId('kea-series-banner')).toBeNull()
    unmount()
    db.alerts = [alert('A1'), alert('A4', { node_id: 'N2' })]
    show()
    // One line for the cluster, naming both nodes.
    const rows = await screen.findAllByTestId('kea-series-banner-row')
    expect(rows).toHaveLength(1)
    await waitFor(() => expect(rows[0]).toHaveTextContent('Kea 2.6 on ns1, N2'))
  })

  it('keeps open alerts of its kind only', () => {
    expect(obsoleteSeries([alert('A1', { details: {} }), alert('A2', { state: 'resolved' })])).toEqual([
      { id: 'A1', nodeId: 'N1', series: '?', eol: null },
    ])
  })

  it('warns about the reduced mode of a Kea 2.6 node on the edit pages only', async () => {
    db.servers = [{ node_id: 'N1', capabilities: { version: '2.6.3' } }, { node_id: 'N2', capabilities: { version: '3.2.1' } }]
    const { unmount } = show('/dhcp/v4/subnets')
    const banner = await screen.findByTestId('kea-reduced-banner')
    expect(banner).toHaveTextContent('Reduced mode on ns1 (Kea 2.6)')
    expect(banner).toHaveTextContent('comments are lost')
    unmount()
    show('/dhcp/v4/leases')
    await waitFor(() => expect(db.calls.length).toBeGreaterThan(0))
    expect(screen.queryByTestId('kea-reduced-banner')).toBeNull()
  })

  it('shows no reduced-mode banner when every node runs Kea 3', async () => {
    db.servers = [{ node_id: 'N1', capabilities: { version: '3.0.1' } }]
    show('/dhcp/v4/subnets')
    await waitFor(() => expect(db.calls.length).toBeGreaterThan(0))
    expect(screen.queryByTestId('kea-reduced-banner')).toBeNull()
  })
})
