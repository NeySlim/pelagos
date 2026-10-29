// SPDX-License-Identifier: Apache-2.0
// DNS > Resolver > Health: readings, probes and thresholds per node, the fallback form sent with
// the right body (from the button or ?fallback=1), the banner with return and extension.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../../i18n'

const db = vi.hoisted(() => ({ health: null, perms: null, settings: { resolver: { fallback_max_hours: 12 } } }))
const calls = vi.hoisted(() => ({ fallbackPlan: vi.fn(), returnPlan: vi.fn(), extend: vi.fn(), series: vi.fn(), info: vi.fn() }))

vi.mock('../../hooks/useWebSocket', () => ({ useWebSocket: () => ({ isConnected: true }), useWsTopic: () => {} }))
vi.mock('../../services/api', () => {
  const plan = (summary) => ({ id: 'P1', summary, changes: [], validations: [] })
  const api = {
    dns: {
      resolver: async () => ({ recursion: true, allow_recursion: ['internal'], forwarders: [], forward: null, dnssec_validation: 'auto', per_node: {} }),
      zones: async () => ({ items: [] }),
      handover: async () => ({ items: [] }),
    },
    resolverHealth: {
      health: async () => db.health,
      series: async (q) => {
        calls.series(q)
        return { series: [{ key: { node_id: 'N1', metric: q.metric }, points: [[1000, 120], [2000, 140]] }], unavailable: [] }
      },
      fallbackPlan: async (body) => {
        calls.fallbackPlan(body)
        return plan('fallback plan')
      },
      returnPlan: async () => {
        calls.returnPlan()
        return plan('return plan')
      },
      extend: async (until) => {
        calls.extend(until)
        return { fallback: { ...db.health.fallback, until } }
      },
    },
    admin: { settings: async () => db.settings },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))
vi.mock('../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: calls.info, showToast: vi.fn() }),
}))
vi.mock('../../components/PlanPreview', () => ({ PlanPreviewModal: ({ plan }) => (plan ? <div data-testid="plan-preview">{plan.summary}</div> : null) }))

vi.mock('../../components/DashboardChart', () => ({ TrendAreaChart: ({ data, series }) => <div data-testid="trend" data-rows={data.length} data-lines={series.length} /> }))

const { default: ResolverPage } = await import('./ResolverPage')

const PRESETS = [
  { id: 'quad9', name: 'Quad9', forwarders: ['9.9.9.9', '149.112.112.112'], tls_name: 'dns.quad9.net', filtering: true, builtin: true },
  { id: 'cloudflare', name: 'Cloudflare', forwarders: ['1.1.1.1'], tls_name: 'one.one.one.one', filtering: false, builtin: true },
]
const node = (id, extra = {}) => ({
  node_id: id,
  sampled_at: new Date().toISOString(),
  error: null,
  rates: { queries_out: 12.5, timeouts_percent: 0.4, servfail_out_percent: 0.8, servfail_clients_percent: 0.3, valfail_percent: 0.01, cache_hit_percent: 82.5 },
  latency_ms: { p50: 24, p95: 180 },
  cache: { nodes: 1000, memory_bytes: 1000000, lru_per_minute: 0 },
  roots: [
    { letter: 'a', address: '198.51.100.1', family: 4, rtt_ms: 12, ok: true, last_failure: null },
    { letter: 'a', address: '2001:db8::1', family: 6, rtt_ms: 14, ok: true, last_failure: null },
    { letter: 'b', address: '198.51.100.2', family: 4, rtt_ms: null, ok: false, last_failure: '2026-10-29T08:00:00Z' },
  ],
  tlds: [
    { tld: 'com', servers: 2, ok: true, rtt_ms: 30, last_failure: null, served: false },
    { tld: 'lan', servers: 2, ok: false, rtt_ms: null, last_failure: '2026-10-29T08:00:00Z', served: true },
  ],
  probes_healthy_since: null,
  observed_max_7d: {},
  ...extra,
})
const THRESHOLDS = {
  latency_p95_ms: { warning: 800, critical: 1600, observed_max_7d: 410 },
  timeouts_percent: { warning: 10, critical: 30, observed_max_7d: 12 },
  tld_failures: { warning: 3, observed_max_7d: 1 },
  mismatch_count: { warning: 100, observed_max_7d: null },
  lru_per_minute: { info: 100, observed_max_7d: 0 },
}
const health = (extra = {}) => ({ nodes: [node('N1'), node('N2', { latency_ms: { p50: 900, p95: 1700 } })], unavailable: [], fallback: null, return_ready: false, thresholds: THRESHOLDS, presets: PRESETS, ...extra })
const FALLBACK = {
  id: '01JF', node_ids: ['N1', 'N2'], preset: 'quad9', forwarders: ['9.9.9.9', '149.112.112.112'], forward: 'first', tls_name: 'dns.quad9.net',
  started_at: '2026-10-29T08:00:00Z', until: new Date(Date.now() + 3 * 3600000 + 600000).toISOString(), by: 'admin', before: {}, returned: ['N2'], manual_change: false,
}

const renderPage = (path = '/dns/resolver') => render(<MemoryRouter initialEntries={[path]}><ResolverPage /></MemoryRouter>)

beforeEach(() => {
  Object.values(calls).forEach((f) => f.mockReset())
  db.health = health()
  db.perms = null
})

describe('Resolver health', () => {
  it('shows the readings, root and TLD probes and thresholds of each node', async () => {
    renderPage()
    const cards = await screen.findAllByTestId('resolver-node')
    expect(cards.map((c) => c.dataset.node)).toEqual(['N1', 'N2'])
    expect(within(cards[0]).getByTestId('resolver-reading-p95')).toHaveAttribute('data-tone', 'success')
    expect(within(cards[0]).getByTestId('resolver-reading-p95')).toHaveTextContent('180 ms')
    expect(within(cards[1]).getByTestId('resolver-reading-p95')).toHaveAttribute('data-tone', 'danger')
    expect(within(cards[0]).getByTestId('resolver-roots-badge')).toHaveTextContent('1/2 root servers answer')
    const roots = within(cards[0]).getByTestId('resolver-roots')
    expect(within(roots).getByText('2001:db8::1')).toBeInTheDocument()
    expect(within(roots).getAllByText('no answer')).toHaveLength(1)
    const tlds = within(cards[0]).getByTestId('resolver-tlds')
    expect(within(tlds).getByText('served')).toBeInTheDocument()
    const thresholds = screen.getByTestId('resolver-thresholds')
    expect(within(thresholds).getByText('800 / 1600')).toBeInTheDocument()
    expect(within(thresholds).getByText('12')).toHaveClass('status-warning-text')
    await waitFor(() => expect(calls.series).toHaveBeenCalledWith(expect.objectContaining({ metric: 'latency_p95_ms', step: 900 })))
    await waitFor(() => expect(screen.getByTestId('trend')).toHaveAttribute('data-rows', '2'))
    fireEvent.click(screen.getByTestId('resolver-range-7d'))
    await waitFor(() => expect(calls.series).toHaveBeenLastCalledWith(expect.objectContaining({ step: 3600 })))
    expect(screen.queryByTestId('resolver-fallback-banner')).toBeNull()
  })

  it('says which nodes did not answer and a node without measures', async () => {
    db.health = health({ nodes: [node('N1', { error: 'no resolver measure yet', rates: {}, latency_ms: {} })], unavailable: [{ node_id: 'N2', name: 'ns2', error: 'timeout' }] })
    renderPage()
    expect(await screen.findByTestId('resolver-health-unavailable')).toHaveTextContent('ns2')
    expect(screen.getByTestId('resolver-node-error')).toHaveTextContent('no resolver measure yet')
    expect(screen.getByTestId('resolver-reading-p95')).toHaveTextContent('-')
  })

  it('builds the fallback plan from the default preset, with a subset of nodes and DNS over TLS', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('resolver-fallback-open'))
    const form = await screen.findByTestId('resolver-fallback-form')
    expect(within(form).getByText('9.9.9.9')).toBeInTheDocument()
    expect(within(form).getByTestId('resolver-fallback-preset-note')).toHaveTextContent('blocks known malicious domains')
    const nodes = within(form).getAllByTestId('resolver-fallback-node')
    expect(nodes).toHaveLength(2)
    fireEvent.click(nodes[1])
    fireEvent.click(within(form).getByRole('switch'))
    fireEvent.click(within(form).getByRole('button', { name: 'Preview the plan' }))
    await waitFor(() => expect(calls.fallbackPlan).toHaveBeenCalledWith({ forwarders: ['9.9.9.9', '149.112.112.112'], forward: 'first', hours: 12, preset: 'quad9', tls: true, node_ids: ['N1'] }))
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('fallback plan')
    await waitFor(() => expect(screen.queryByTestId('resolver-fallback-form')).toBeNull())
  })

  it('refuses a form without nodes, and opens from the alert link', async () => {
    renderPage('/dns/resolver?fallback=1')
    const form = await screen.findByTestId('resolver-fallback-form')
    for (const box of within(form).getAllByTestId('resolver-fallback-node')) fireEvent.click(box)
    fireEvent.click(within(form).getByRole('button', { name: 'Preview the plan' }))
    expect(await within(form).findByText('Choose at least one node')).toBeInTheDocument()
    expect(calls.fallbackPlan).not.toHaveBeenCalled()
  })

  it('shows the active fallback with return and extension', async () => {
    db.health = health({ fallback: FALLBACK, return_ready: true })
    renderPage()
    const banner = await screen.findByTestId('resolver-fallback-banner')
    expect(within(banner).getByTestId('resolver-fallback-forwarders')).toHaveTextContent('9.9.9.9, 149.112.112.112')
    expect(banner).toHaveTextContent('DNS over TLS: dns.quad9.net')
    expect(banner).toHaveTextContent('already back: ns2')
    expect(within(banner).getByTestId('resolver-fallback-until')).toHaveTextContent(/3 h 9 min left|3 h 10 min left/)
    expect(within(banner).getByTestId('resolver-fallback-ready')).toBeInTheDocument()
    expect(screen.queryByTestId('resolver-fallback-open')).toBeNull()
    fireEvent.click(within(banner).getByTestId('resolver-fallback-return'))
    await waitFor(() => expect(calls.returnPlan).toHaveBeenCalled())
    expect(await screen.findByTestId('plan-preview')).toHaveTextContent('return plan')
    fireEvent.click(within(banner).getByTestId('resolver-fallback-extend'))
    const form = await screen.findByTestId('resolver-extend-form')
    const before = Date.now()
    fireEvent.click(within(form).getByRole('button', { name: 'Extend' }))
    await waitFor(() => expect(calls.extend).toHaveBeenCalled())
    const until = Date.parse(calls.extend.mock.calls[0][0])
    expect(until - before).toBeGreaterThanOrEqual(4 * 3600000 - 61000)
    expect(until - before).toBeLessThan(4 * 3600000)
  })

  it('hides the fallback actions without write:dns.config', async () => {
    db.perms = ['read:dns', 'read:series']
    db.health = health({ fallback: FALLBACK })
    renderPage('/dns/resolver?fallback=1')
    const banner = await screen.findByTestId('resolver-fallback-banner')
    expect(within(banner).queryByTestId('resolver-fallback-return')).toBeNull()
    expect(screen.queryByTestId('resolver-fallback-open')).toBeNull()
    expect(screen.queryByTestId('resolver-fallback-form')).toBeNull()
    await waitFor(() => expect(calls.info).toHaveBeenCalledWith('A forwarder fallback is already active: see the banner.'))
  })

  it('leaves a silent node unticked and names its error, so the plan carries node_ids', async () => {
    db.health = health({ nodes: [node('N1')], unavailable: [{ node_id: 'N2', name: 'ns2', error: 'release 0.2.2 required' }] })
    renderPage('/dns/resolver?fallback=1')
    expect(await screen.findByTestId('resolver-health-unavailable')).toHaveTextContent('ns2 (release 0.2.2 required)')
    const form = await screen.findByTestId('resolver-fallback-form')
    const boxes = within(form).getAllByTestId('resolver-fallback-node')
    expect(boxes.map((b) => b.checked)).toEqual([true, false])
    expect(within(form).getByTestId('resolver-fallback-node-error')).toHaveTextContent('release 0.2.2 required')
    fireEvent.click(within(form).getByRole('button', { name: 'Preview the plan' }))
    await waitFor(() => expect(calls.fallbackPlan).toHaveBeenCalledWith(expect.objectContaining({ node_ids: ['N1'] })))
  })

  it('drops ?fallback=1 for a read only role and says why', async () => {
    db.perms = ['read:dns', 'read:series']
    renderPage('/dns/resolver?fallback=1')
    await waitFor(() => expect(calls.info).toHaveBeenCalledWith('Proposing a fallback needs the write:dns.config permission.'))
    expect(screen.queryByTestId('resolver-fallback-form')).toBeNull()
  })
})
