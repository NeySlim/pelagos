// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { RadarTile, DnsTile, DhcpTile } from './heroTiles'
import { summarizeLive } from '../../lib/liveRates'

const N1 = 'N1'
const N2 = 'N2'
const node = (id, name, self, status = 'online') => ({ peer: { id, name }, is_self: self, status })
const SUMMARY = {
  nodes: [node(N1, 'ns1', true), node(N2, 'ns2', false)],
  ha: [
    { node_id: N1, family: 'v4', server_name: 'ns1', role: 'primary', state: 'hot-standby', partner: { in_touch: true } },
    { node_id: N2, family: 'v4', server_name: 'ns2', role: 'standby', state: 'partner-down', partner: { in_touch: false } },
  ],
  pools: [
    { node_id: N1, engine: 'kea4', subnet_id: 1, subnet: '192.0.2.0/24', pool: '192.0.2.10 - 192.0.2.19', total: 10, assigned: 9, percent: 90 },
    { node_id: N1, engine: 'kea4', subnet_id: 2, subnet: '192.0.2.0/24', pool: '192.0.2.20 - 192.0.2.29', total: 10, assigned: 1, percent: 10 },
  ],
  zones: [
    { zone: 'example.lan.', view: '_default', serials: { [N1]: 5, [N2]: 5 }, divergent: false },
    { zone: 'lab.example.lan.', view: '_default', serials: { [N1]: 7, [N2]: 6 }, divergent: true },
  ],
}
const pts = (...values) => values.map((v, i) => ({ t: 1000 * (i + 1), v }))
const TARGETS = [
  { key: 'dns:N1', kind: 'dns', node: N1 },
  { key: 'dns:N2', kind: 'dns', node: N2 },
  { key: 'dhcp:v4:N1', kind: 'dhcp', node: N1 },
]
const LIVE = summarizeLive(TARGETS, {
  'dns:N1': { points: pts(100, 120, 140), parts: { NOERROR: pts(90, 100, 120), NXDOMAIN: pts(10, 20, 20) } },
  'dns:N2': { points: pts(50, 60, 60), parts: { NOERROR: pts(50, 60, 60), NXDOMAIN: pts(0, 0, 0) } },
  'dhcp:v4:N1': { points: pts(3, 4, 5), parts: {} },
})
const props = { summary: SUMMARY, editing: false, nameOf: (id) => id, live: LIVE, openAlerts: [{ id: 'x', node_id: N2, severity: 'critical', title: 'key' }, { id: 'y', node_id: null, severity: 'warning', title: 'cluster' }] }
const wrap = (ui) => render(<MemoryRouter>{ui}</MemoryRouter>)

describe('hero tiles', () => {
  it('draws the cluster on the radar with rates, links, alerts and the HA rail', () => {
    wrap(<RadarTile {...props} />)
    const radar = screen.getByTestId('cluster-radar')
    // jsdom has no layout: the stage reports no size, so only the frame renders.
    expect(radar).toBeInTheDocument()
    expect(screen.getByTestId('radar-controls').querySelectorAll('button')).toHaveLength(4)
    expect(screen.getByTestId('radar-chips')).toBeInTheDocument()
  })

  it('places pins, links, markers and pills once the stage has a size', () => {
    const rect = vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({ width: 640, height: 420, top: 0, left: 0, right: 640, bottom: 420, x: 0, y: 0 })
    try {
      wrap(<RadarTile {...props} />)
      const pins = screen.getAllByTestId('radar-node')
      expect(pins.map((p) => p.textContent)).toEqual([expect.stringContaining('ns1'), expect.stringContaining('ns2')])
      expect(pins[0]).toHaveTextContent('140 q/s')
      // ns2 carries a critical alert: yellow pin with its count.
      expect(pins[1]).toHaveAttribute('data-tone', 'warning')
      expect(screen.getByTestId('radar-link')).toHaveAttribute('data-state', 'lag')
      expect(screen.getAllByTestId('radar-alert')).toHaveLength(1)
      expect(screen.getAllByTestId('radar-ha-pill').map((p) => p.dataset.tone)).toEqual(['primary', 'danger'])
      expect(screen.getByTestId('radar-readout')).toHaveTextContent('200')
    } finally {
      rect.mockRestore()
    }
  })

  it('shows the DNS rate, the NXDOMAIN share and the rcode rows', () => {
    wrap(<DnsTile {...props} />)
    const tile = screen.getByTestId('tile-dns')
    expect(within(screen.getByTestId('dns-rate')).getByText('200', { selector: '.sr-only' })).toBeInTheDocument()
    expect(within(tile).getAllByTestId('dns-rcode')).toHaveLength(4)
    expect(within(tile).getByText('10 %', { selector: '.sr-only' })).toBeInTheDocument()
    expect(within(tile).getByTestId('stippled-area-chart')).toBeInTheDocument()
  })

  it('waits for two samples before drawing', () => {
    wrap(<DnsTile {...props} live={summarizeLive(TARGETS, {})} />)
    expect(screen.getByTestId('tile-collecting')).toBeInTheDocument()
  })

  it('lists pools as segments and HA servers as pills', () => {
    wrap(<DhcpTile {...props} />)
    const tile = screen.getByTestId('tile-dhcp')
    expect(within(screen.getByTestId('dhcp-rate')).getByText('5', { selector: '.sr-only' })).toBeInTheDocument()
    const bars = within(tile).getAllByRole('progressbar')
    expect(bars[0]).toHaveAttribute('aria-valuenow', '90')
    const pills = within(tile).getAllByTestId('dhcp-ha-pill')
    expect(pills[0]).toHaveClass('fx-tone-primary')
    expect(pills[1]).toHaveClass('fx-tone-danger')
  })
})
