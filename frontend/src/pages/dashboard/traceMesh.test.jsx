// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { TraceTile } from './traceTile'
import { meshModel, meshStatus } from './traceModel'
import { linkCurve, pointOn } from '../../components/motion/meshGeometry'
import { resetClusterSignals } from '../../hooks/useClusterSignals'

vi.mock('../../contexts/AuthContext', () => ({
  useAuth: () => ({ permissions: ['*'], hasPermission: () => true, isAdmin: true, modules: { dhcpv6: false } }),
}))
vi.mock('../../services/api', () => ({ api: { dhcp: { ha: async () => ({ items: [] }) } } }))

const node = (id, self = false, extra = {}) => ({
  peer: { id, name: id, modules: { bind: true, kea4: true, kea6: false, d2: false } },
  is_self: self,
  status: 'online',
  version: '0.1.0',
  config_version: 42,
  audit_count: 318,
  ...extra,
})
const ha = (id, role, state, partner = null, inTouch = true) => ({
  node_id: id,
  family: 'v4',
  server_name: id,
  role,
  state,
  enabled: true,
  partner: partner ? { server_name: partner, in_touch: inTouch, state: 'hot-standby' } : null,
})
const PAIR = [ha('ns1', 'primary', 'hot-standby', 'ns2'), ha('ns2', 'standby', 'hot-standby', 'ns1')]

describe('mesh model', () => {
  it('orders the pair, the backups, then the rest, and links every node', () => {
    const nodes = [node('ns4'), node('ns3'), node('ns5'), node('ns2'), node('ns1', true)]
    const { cards, links } = meshModel(nodes, [...PAIR, ha('ns3', 'backup', 'backup'), ha('ns4', 'backup', 'backup')])
    expect(cards.map((c) => `${c.id}:${c.role}`)).toEqual(['ns1:primary', 'ns2:standby', 'ns3:backup', 'ns4:backup', 'ns5:null'])
    expect(links.filter((l) => l.kind === 'repl')).toHaveLength(10) // 5 nodes, every pair
    expect(links.filter((l) => l.kind === 'ha')).toEqual([{ kind: 'ha', a: 'ns1', b: 'ns2', state: 'ok' }])
    expect(links.filter((l) => l.kind === 'feed').map((l) => `${l.a}>${l.b}`)).toEqual(['ns1>ns3', 'ns1>ns4'])
  })

  it('marks the links of an offline node, a lost partner and a backup out of its state', () => {
    const nodes = [node('ns1', true), node('ns2'), node('ns3', false, { status: 'offline' })]
    const states = [ha('ns1', 'primary', 'partner-down', 'ns2', false), ha('ns2', 'standby', 'unavailable', 'ns1', false), ha('ns3', 'backup', 'waiting')]
    const { links } = meshModel(nodes, states)
    const of = (kind, a, b) => links.find((l) => l.kind === kind && l.a === a && l.b === b)
    expect(of('repl', 'ns1', 'ns2').state).toBe('ok')
    expect(of('repl', 'ns1', 'ns3').state).toBe('down')
    expect(of('ha', 'ns1', 'ns2').state).toBe('down')
    // The primary lost its partner but still serves: it feeds the backup.
    expect(of('feed', 'ns1', 'ns3').state).toBe('down')
  })

  it('says in sync, behind or unreachable for the whole cluster', () => {
    const self = node('ns1', true, { config_version: 44 })
    expect(meshStatus(self, [self, node('ns2', false, { config_version: 44 }), node('ns3', false, { config_version: 44 })])).toMatchObject({ status: 'inSync', count: 3 })
    expect(meshStatus(self, [self, node('ns2', false, { config_version: 43 }), node('ns3', false, { config_version: 41 })])).toMatchObject({ status: 'behind', names: ['ns2', 'ns3'], count: 3 })
    expect(meshStatus(self, [self, node('ns2', false, { status: 'offline' }), node('ns3')])).toMatchObject({ status: 'unreachable', names: ['ns2'] })
  })

  it('draws replication arcs above the row, higher for distant nodes, and feeds below', () => {
    const box = (i) => ({ x: i * 120, y: 30, w: 100, h: 50 })
    const near = linkCurve('repl', box(0), box(1), 1)
    const far = linkCurve('repl', box(0), box(3), 3)
    expect(near[1][1]).toBeLessThan(30)
    expect(far[1][1]).toBeLessThan(near[1][1])
    expect(linkCurve('feed', box(0), box(2), 2)[1][1]).toBeGreaterThan(80)
    const haLink = linkCurve('ha', box(0), box(1), 1)
    expect(haLink[0]).toEqual([100, 55])
    expect(haLink[2]).toEqual([120, 55])
    expect(pointOn(near, 0)).toEqual(near[0])
    expect(pointOn(near, 1)).toEqual(near[2])
  })
})

describe('cluster trace with more than two nodes', () => {
  beforeEach(() => resetClusterSignals())
  const wrap = (summary) => render(<MemoryRouter><TraceTile summary={summary} editing={false} live={null} /></MemoryRouter>)

  it('draws a card per node with its role, and the mesh of links', () => {
    const nodes = [node('ns1', true), node('ns2'), node('ns3'), node('ns4', false, { config_version: 41 })]
    wrap({ nodes, ha: [...PAIR, ha('ns3', 'backup', 'backup'), ha('ns4', 'backup', 'backup')], zones: [] })
    const tile = screen.getByTestId('tile-trace')
    expect(within(tile).getByTestId('trace-topology')).toHaveAttribute('data-nodes', '4')
    const cards = within(tile).getAllByTestId('trace-node')
    expect(cards.map((c) => c.getAttribute('data-role'))).toEqual(['primary', 'standby', 'backup', 'backup'])
    expect(cards[0]).toHaveTextContent('this node')
    expect(cards[2]).toHaveClass('is-backup')
    // 6 replication arcs, the HA link and two feeds.
    expect(within(tile).getByTestId('trace-mesh-links')).toHaveAttribute('data-links', '9')
    expect(within(tile).getByTestId('trace-mesh-status')).toHaveTextContent('ns4 behind by 1')
    expect(within(tile).queryByTestId('trace-link')).toBeNull()
  })

  it('scales to eight nodes', () => {
    const nodes = Array.from({ length: 8 }, (_, i) => node(`ns${i + 1}`, i === 0))
    const states = [...PAIR, ...nodes.slice(2, 6).map((n) => ha(n.peer.id, 'backup', 'backup'))]
    wrap({ nodes, ha: states, zones: [] })
    expect(screen.getAllByTestId('trace-node')).toHaveLength(8)
    expect(screen.getByTestId('trace-mesh-links')).toHaveAttribute('data-links', String(28 + 1 + 4))
    expect(screen.getByTestId('trace-mesh-status')).toHaveTextContent('8 nodes in sync')
  })
})
