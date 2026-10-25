// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { DnsTile, DhcpTile } from './heroTiles'
import { RadarTile } from './radarTile'
import { TraceTile } from './traceTile'
import { summarizeLive } from '../../lib/liveRates'
import { resetClusterSignals } from '../../hooks/useClusterSignals'

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ permissions: ['*'], hasPermission: () => true, isAdmin: true, modules: { dhcpv6: true } }),
}))
const haCalls = vi.fn()
vi.mock('../../services/api', () => ({
  api: {
    dhcp: {
      ha: async (family) => {
        haCalls(family)
        return { items: [] }
      },
    },
  },
}))

const N1 = 'N1'
const N2 = 'N2'
const node = (id, name, self, status = 'online', config = 42) => ({ peer: { id, name, modules: { bind: true, kea4: true, kea6: false, d2: true } }, is_self: self, status, version: '0.1.0', config_version: config, audit_count: 318 })
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
  'dhcp:v4:N1': { points: pts(3, 4, 5), parts: { discover: pts(3, 3, 3.2), offer: pts(3, 3, 3.1), request: pts(5, 6, 6.5), ack: pts(3, 4, 5), nak: pts(0, 0, 0) } },
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
    expect(within(tile).getByText('10', { selector: '.sr-only' })).toBeInTheDocument()
    const strip = within(tile).getByTestId('dns-strip')
    expect(strip).toHaveAttribute('data-count', '3')
    expect(within(strip).getByTestId('readout')).toHaveTextContent('CH1')
  })

  it('waits for two samples before drawing', () => {
    wrap(<DnsTile {...props} live={summarizeLive(TARGETS, {})} />)
    expect(screen.getByTestId('tile-collecting')).toBeInTheDocument()
  })

  it('shows the lease strip, the latest exchange, pools against thresholds and HA pills', () => {
    wrap(<DhcpTile {...props} />)
    const tile = screen.getByTestId('tile-dhcp')
    expect(within(screen.getByTestId('dhcp-rate')).getByText('5', { selector: '.sr-only' })).toBeInTheDocument()
    expect(within(tile).getByTestId('dhcp-strip')).toBeInTheDocument()
    // 5 leases/s over the 1 s between the last two samples.
    const latest = within(tile).getByTestId('dhcp-latest')
    expect(latest).toHaveTextContent('+5 leases')
    expect(within(latest).getByTestId('dora')).toHaveClass('is-on')
    expect(within(latest).getByTestId('dora')).not.toHaveClass('is-nak')
    expect(latest).toHaveTextContent('3.2')
    const bars = within(tile).getAllByRole('progressbar')
    expect(bars[0]).toHaveAttribute('aria-valuenow', '90')
    expect(within(tile).getAllByTestId('dhcp-pool')[0]).toHaveClass('is-hot')
    const pills = within(tile).getAllByTestId('dhcp-ha-pill')
    expect(pills[0]).toHaveClass('fx-tone-primary')
    expect(pills[1]).toHaveClass('fx-tone-danger')
  })

  it('gives each HA server one pill with its families, in the tone of the worst', () => {
    const ha = [
      ...SUMMARY.ha,
      { node_id: N1, family: 'v6', server_name: 'ns1', role: 'primary', state: 'waiting', partner: { in_touch: true } },
      { node_id: N2, family: 'v6', server_name: 'ns2', role: 'standby', state: 'hot-standby', partner: { in_touch: true } },
    ]
    wrap(<DhcpTile {...props} summary={{ ...SUMMARY, ha }} />)
    const pills = within(screen.getByTestId('tile-dhcp')).getAllByTestId('dhcp-ha-pill')
    expect(pills).toHaveLength(2)
    expect(pills[0]).toHaveTextContent('ns1v4 · v6')
    expect(pills[0]).toHaveClass('fx-tone-warning')
    expect(pills[0]).toHaveAttribute('href', '/dhcp/v6/ha')
    expect(pills[1]).toHaveClass('fx-tone-danger')
    expect(pills[1]).toHaveAttribute('href', '/dhcp/v4/ha')
  })

  it('draws no latest exchange row while live counters are collected', () => {
    wrap(<DhcpTile {...props} live={summarizeLive(TARGETS, {})} />)
    expect(within(screen.getByTestId('tile-dhcp')).queryByTestId('dhcp-latest')).toBeNull()
  })

  describe('cluster trace', () => {
    beforeEach(() => {
      resetClusterSignals()
      haCalls.mockClear()
    })

    it('draws both nodes, their link and the trace lanes', async () => {
      wrap(<TraceTile {...props} samples={12} />)
      const tile = screen.getByTestId('tile-trace')
      const cards = within(tile).getAllByTestId('trace-node')
      expect(cards.map((c) => c.textContent)).toEqual([expect.stringContaining('ns1'), expect.stringContaining('ns2')])
      expect(cards[0]).toHaveTextContent('this node')
      expect(cards[0]).toHaveTextContent('BIND')
      expect(cards[0]).not.toHaveTextContent('DHCPv6')
      // ns2 lost touch with its partner: the link is down.
      expect(within(tile).getByTestId('trace-link')).toHaveAttribute('data-state', 'down')
      expect(within(tile).getByTestId('trace-link')).toHaveTextContent('ns2 unreachable')
      expect(within(tile).getByTestId('cluster-trace')).toHaveAttribute('data-window', '90000')
      expect(within(tile).getByTestId('trace-dns-rate')).toHaveTextContent('200')
      expect(within(tile).getByTestId('trace-count')).toHaveTextContent('00012')
      expect(within(tile).getByTestId('trace-last-event')).toHaveTextContent('none yet')
      await waitFor(() => expect(haCalls).toHaveBeenCalledWith('v4'))
    })

    it('changes the window from the range segment and keeps it for the session', () => {
      wrap(<TraceTile {...props} />)
      fireEvent.click(screen.getByRole('button', { name: '30 s' }))
      expect(screen.getByTestId('cluster-trace')).toHaveAttribute('data-window', '30000')
      expect(screen.getByRole('button', { name: '30 s' })).toHaveAttribute('aria-pressed', 'true')
      expect(screen.getByTestId('scalebar')).toHaveTextContent('10 s')
      fireEvent.click(screen.getByRole('button', { name: '5 min' }))
      expect(screen.getByTestId('scalebar')).toHaveTextContent('1 min')
      expect(sessionStorage.getItem('pelagos-trace-window')).toBe('300000')
      sessionStorage.removeItem('pelagos-trace-window')
    })

    it('says how far the peer is behind when the link is up', () => {
      const summary = { ...SUMMARY, nodes: [node(N1, 'ns1', true, 'online', 43), node(N2, 'ns2', false, 'online', 42)], ha: [] }
      wrap(<TraceTile {...props} summary={summary} />)
      expect(screen.getByTestId('trace-link')).toHaveAttribute('data-state', 'ok')
      expect(screen.getByTestId('trace-link')).toHaveTextContent('ns2 behind by 1')
      expect(screen.queryByTestId('trace-heartbeat')).toBeNull()
    })
  })
})
