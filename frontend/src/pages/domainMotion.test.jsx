// SPDX-License-Identifier: Apache-2.0
// Wiring of the contextual animations: each simulated WebSocket event (or plan state) sets
// off the primitive it belongs to on the page that shows it, and nothing else; at `off`
// nothing animates, at `reduced` nothing travels.
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { MotionProvider } from '../contexts/MotionContext'
import { emitPlanEvent, onPlanEvent } from '../lib/planEvents'
import { resetEstimates } from '../lib/planTrace'

const bus = vi.hoisted(() => new Map())
const db = vi.hoisted(() => ({}))

vi.mock('../hooks/useWebSocket', async () => {
  const { useEffect, useRef } = await import('react')
  return {
    WsState: { CONNECTED: 'connected', DISCONNECTED: 'disconnected' },
    WebSocketProvider: ({ children }) => children,
    useWebSocket: () => ({ state: 'connected', isConnected: true, lastMessage: null, subscribe: () => () => {}, connect: () => {}, ping: () => true }),
    useWsTopic: (topic, handler) => {
      const ref = useRef(handler)
      ref.current = handler
      useEffect(() => {
        if (!topic) return undefined
        const fn = (m) => ref.current?.(m)
        if (!bus.has(topic)) bus.set(topic, new Set())
        bus.get(topic).add(fn)
        return () => bus.get(topic).delete(fn)
      }, [topic])
    },
  }
})
vi.mock('../services/api', () => {
  const api = {
    dhcp: {
      ha: async () => ({ items: db.ha }),
      servers: async () => ({ items: [] }),
      haTransitions: async () => ({ items: [] }),
      configFile: async () => ({}),
      leases: async () => ({ items: db.leases, meta: {} }),
      recentLeases: async () => ({ items: [...db.leases].sort((a, b) => b.cltt.localeCompare(a.cltt)).slice(0, 1) }),
    },
    d2: { configFile: async () => ({}) },
    nodes: { list: async () => ({ items: db.nodes }), replication: async () => ({ state: 'ready', peers: db.peers }) },
    alerts: { summary: async () => ({ open: db.alerts.length, acked: 0, by_severity: {} }), list: async () => ({ items: db.alerts, total: db.alerts.length, page: 1, per_page: 50 }) },
    series: { serials: async () => ({ series: [] }), pools: async () => ({ series: [] }) },
    dashboard: { summary: async () => ({}) },
  }
  return { api, default: api }
})
vi.mock('../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))
vi.mock('../contexts/AuthContext', () => ({ useAuth: () => ({ modules: { dhcpv6: true } }) }))
vi.mock('../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn(), showPrompt: vi.fn() }),
}))

const { PlanPreview } = await import('../components/PlanPreview')
const { default: HaPage } = await import('./dhcp/HaPage')
const { default: NodesPage } = await import('./nodes/NodesPage')
const { default: AlertsPage } = await import('./alerts/AlertsPage')
const { LatestLease } = await import('./dashboard/LatestLease')
const { ZoneSerialTrace } = await import('./dns/ZoneSerialTrace')

const publish = (topic, event, data) =>
  act(() => {
    for (const fn of [...(bus.get(topic) || [])]) fn({ topic, event, data, ts: new Date().toISOString() })
  })

const renderAt = (level, ui) => {
  localStorage.setItem('pelagos-preferences', JSON.stringify({ animations: level }))
  return render(
    <MemoryRouter>
      <MotionProvider>{ui}</MotionProvider>
    </MemoryRouter>,
  )
}

const deferred = () => {
  let resolve
  const promise = new Promise((r) => {
    resolve = r
  })
  return { promise, resolve }
}

const PLAN = {
  id: 'PLAN1',
  created_at: new Date(Date.now() - 1000).toISOString(),
  created_by: 'admin',
  node_id: 'n1',
  scope: 'dns.rrset',
  engine: 'bind',
  summary: '1 change in example.lan.',
  changes: [{ op: 'add', target: 'example.lan./www2/A', node_ids: [] }],
  diff: '',
  preconditions: [],
  validations: [
    { ok: true, tool: 'named-checkzone', output: 'OK', node_id: 'n1' },
    { ok: true, tool: 'dnspython', output: '', node_id: 'n1' },
  ],
  target_node_ids: ['n1', 'n2'],
  requires_confirmation: false,
  state: 'validated',
  expires_at: new Date(Date.now() + 599000).toISOString(),
}
const RESULT = (state) => ({
  plan_id: 'PLAN1',
  state,
  results: [
    { node_id: 'n1', ok: true, message: 'NOERROR', rolled_back: state === 'rolled_back' },
    { node_id: 'n2', ok: true, message: 'NOERROR', rolled_back: state === 'rolled_back' },
  ],
  finished_at: new Date().toISOString(),
})
const nodeAudit = (verb) => ({ plan_id: 'PLAN1', node_id: 'n1', action: `dns.rrset.${verb}`, request: { entry: 'node', verb } })
const steps = () => screen.getAllByTestId('plan-steps-step').map((s) => s.dataset.state)

beforeEach(() => {
  localStorage.clear()
  resetEstimates()
  bus.clear()
  Object.assign(db, { ha: [], leases: [], nodes: [], peers: [], alerts: [] })
})
afterEach(() => vi.restoreAllMocks())

describe('plan procedures', () => {
  it('ticks the validations in order at full, all at once at off', async () => {
    const full = renderAt('full', <PlanPreview plan={PLAN} nodeName={(id) => id} />)
    const checks = () => within(screen.getByTestId('plan-checklist')).getAllByRole('listitem').map((li) => li.dataset.state)
    expect(checks()).toEqual(['running', 'pending'])
    await waitFor(() => expect(checks()).toEqual(['done', 'done']))
    full.unmount()
    renderAt('off', <PlanPreview plan={PLAN} nodeName={(id) => id} />)
    expect(checks()).toEqual(['done', 'done'])
  })

  it('apply: the plan folds, the rail follows the local audit entry then the result; rollback walks back', async () => {
    const events = []
    const off = onPlanEvent((e) => events.push([e.type, e.at !== undefined]))
    const apply = deferred()
    const rollback = deferred()
    renderAt('full', <PlanPreview plan={PLAN} applyFn={() => apply.promise} rollbackFn={() => rollback.promise} getFn={async () => PLAN} nodeName={(id) => ({ n1: 'ns1', n2: 'ns2' })[id]} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    expect(screen.getByTestId('plan-rail')).toHaveAttribute('data-direction', 'forward')
    expect(screen.getByTestId('plan-validations')).toHaveAttribute('data-open', 'false')
    expect(screen.getByTestId('plan-diff')).toHaveAttribute('data-open', 'false')
    expect(steps()).toEqual(['running', 'pending', 'pending'])
    publish('audit', 'entry', { ...nodeAudit('apply'), plan_id: 'OTHER' })
    expect(steps()).toEqual(['running', 'pending', 'pending'])
    publish('audit', 'entry', nodeAudit('apply'))
    expect(steps()).toEqual(['done', 'running', 'pending'])
    expect(screen.getAllByTestId('plan-steps-node').map((n) => [n.textContent, n.dataset.state])).toEqual([['ns1', 'done'], ['ns2', 'running'], ['ns1', 'pending'], ['ns2', 'pending']])
    await act(async () => apply.resolve(RESULT('applied')))
    expect(await screen.findByTestId('plan-result')).toBeInTheDocument()
    expect(steps()).toEqual(['done', 'done', 'done'])

    fireEvent.click(screen.getByTestId('plan-rollback'))
    expect(screen.getByTestId('plan-rail')).toHaveAttribute('data-direction', 'reverse')
    expect(screen.getByTestId('plan-preview')).toHaveAttribute('data-plan-state', 'rolling_back')
    expect(steps()).toEqual(['done', 'running', 'reverted'])
    publish('audit', 'entry', nodeAudit('rollback'))
    expect(steps()).toEqual(['reverted', 'reverted', 'reverted'])
    await act(async () => rollback.resolve(RESULT('rolled_back')))
    await waitFor(() => expect(screen.getByTestId('plan-preview')).toHaveAttribute('data-plan-state', 'rolled_back'))
    off()
    expect(events).toEqual([['applied', true], ['rollback-start', true], ['rolled-back', true]])
  })

  it('job progress on the jobs topic moves the job rail', async () => {
    const job = { id: 'J1', plan_id: 'PLAN1', state: 'running', progress: 0, steps: [{ name: 'backup', state: 'running' }, { name: 'reload', state: 'queued' }] }
    renderAt('reduced', <PlanPreview plan={{ ...PLAN, scope: 'security' }} applyFn={async () => job} jobFn={async () => job} nodeName={(id) => id} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await screen.findByTestId('plan-job')
    const jobSteps = () => screen.getAllByTestId('plan-job-steps-step').map((s) => s.dataset.state)
    expect(jobSteps()).toEqual(['running', 'pending'])
    publish('jobs', 'progress', { ...job, progress: 50, steps: [{ name: 'backup', state: 'done', started_at: '2026-10-25T10:00:00Z', finished_at: '2026-10-25T10:00:00.400Z' }, { name: 'reload', state: 'running' }] })
    expect(jobSteps()).toEqual(['done', 'running'])
    expect(screen.getByTestId('plan-job')).toHaveTextContent('400 ms')
  })

  it('a rollback rewinds the zone serial trace, which returns to the present after', async () => {
    renderAt('reduced', <ZoneSerialTrace zone={{ name: 'example.lan.' }} status={{ n1: { serial: 1 }, n2: { serial: 1 } }} nameOf={(id) => id} />)
    const trace = await screen.findByTestId('serial-trace')
    expect(trace).not.toHaveAttribute('data-scrubbing')
    act(() => emitPlanEvent({ type: 'rollback-start', plan: PLAN, at: Date.now() - 5000 }))
    expect(trace).toHaveAttribute('data-scrubbing', 'true')
    act(() => emitPlanEvent({ type: 'rolled-back', plan: PLAN, at: Date.now(), result: RESULT('rolled_back') }))
    await waitFor(() => expect(trace).not.toHaveAttribute('data-scrubbing'))
    // Another zone's plan leaves this trace alone.
    act(() => emitPlanEvent({ type: 'rollback-start', plan: { ...PLAN, changes: [{ target: 'corp.example.lan./a/A' }] }, at: Date.now() }))
    expect(trace).not.toHaveAttribute('data-scrubbing')
  })
})

const haState = (extra = {}) => ({
  node_id: 'n1', family: 'v4', collected_at: '2026-10-25T10:00:00Z', server_name: 'ns1', mode: 'hot-standby', role: 'primary', state: 'hot-standby',
  scopes: ['ns1'], unsent_update_count: 0, partner: { role: 'standby', state: 'hot-standby', scopes: [], in_touch: true, age: 1 }, enabled: true, ...extra,
})

describe('HA cards', () => {
  it('a heartbeat traces the ECG, unsent updates fill the queue, a lost partner flattens it', async () => {
    db.ha = [haState()]
    const { container } = renderAt('full', <HaPage family="v4" />)
    await screen.findByTestId('ha-server')
    expect(screen.getByTestId('ha-heartbeat')).toHaveAttribute('data-beats', '0')
    publish('ha', 'state', haState({ collected_at: '2026-10-25T10:00:03Z', unsent_update_count: 3 }))
    expect(screen.getByTestId('ha-heartbeat')).toHaveAttribute('data-beats', '1')
    expect(container.querySelector('.fx-ecg-qrs')).toHaveClass('is-beat')
    expect(screen.getByTestId('unsent-queue')).toHaveAttribute('data-count', '3')
    expect(container.querySelectorAll('.fx-queue-slots > i.is-in')).toHaveLength(3)
    publish('ha', 'state', haState({ collected_at: '2026-10-25T10:00:06Z', state: 'partner-down', unsent_update_count: 0, partner: { in_touch: false } }))
    expect(screen.getByTestId('ha-heartbeat')).toHaveClass('is-lost')
    expect(screen.getByTestId('unsent-queue')).toHaveAttribute('data-draining', 'true')
    // Another family's state is not this page's.
    publish('ha', 'state', haState({ family: 'v6', collected_at: '2026-10-25T10:00:09Z' }))
    expect(screen.getByTestId('ha-heartbeat')).toHaveClass('is-lost')
  })

  it('at off the heartbeat and the queue change without motion', async () => {
    db.ha = [haState()]
    const { container } = renderAt('off', <HaPage family="v4" />)
    await screen.findByTestId('ha-server')
    publish('ha', 'state', haState({ collected_at: '2026-10-25T10:00:03Z', unsent_update_count: 2 }))
    expect(screen.getByTestId('ha-heartbeat')).toHaveAttribute('data-beats', '1')
    expect(container.querySelector('.fx-ecg-qrs.is-beat')).toBeNull()
    expect(container.querySelectorAll('.fx-queue-slots > i')).toHaveLength(2)
    expect(container.querySelectorAll('.fx-queue-slots > i.is-in')).toHaveLength(0)
  })
})

const lease = (ip, cltt, state = 'default') => ({ ip_address: ip, cltt, state, hw_address: '02:00:5e:00:00:01', node_id: 'n1', subnet_id: 1 })

describe('DORA', () => {
  it('a lease event plays DORA for a new latest lease, with its client', async () => {
    db.leases = [lease('192.0.2.100', '2026-10-25T10:00:00Z')]
    renderAt('full', <LatestLease family="v4" />)
    await screen.findByTestId('latest-lease')
    expect(screen.getByTestId('dora')).not.toHaveClass('is-go')
    publish('leases', 'lease', { engine: 'kea6', family: 'v6', change: 'new', lease: lease('2001:db8::5', '2026-10-25T10:03:00Z') })
    publish('leases', 'lease', { engine: 'kea4', family: 'v4', change: 'new', lease: { ...lease('192.0.2.124', '2026-10-25T10:01:00Z'), hostname: 'pc124' } })
    await waitFor(() => expect(screen.getByTestId('latest-lease')).toHaveAttribute('data-lease', '192.0.2.124'))
    expect(screen.getByTestId('dora')).toHaveClass('is-go')
    expect(screen.getByTestId('latest-lease-client')).toHaveTextContent('pc124')
    // An older transaction never replaces the newest one.
    publish('leases', 'lease', { engine: 'kea4', family: 'v4', change: 'renewed', lease: lease('192.0.2.101', '2026-10-25T09:00:00Z') })
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.getByTestId('latest-lease')).toHaveAttribute('data-lease', '192.0.2.124')
  })

  it('stands still at off', async () => {
    db.leases = [lease('192.0.2.100', '2026-10-25T10:00:00Z')]
    renderAt('off', <LatestLease family="v4" />)
    await screen.findByTestId('latest-lease')
    publish('leases', 'lease', { engine: 'kea4', family: 'v4', change: 'new', lease: lease('192.0.2.125', '2026-10-25T10:02:00Z', 'declined') })
    await waitFor(() => expect(screen.getByTestId('latest-lease')).toHaveAttribute('data-lease', '192.0.2.125'))
    expect(screen.getByTestId('dora')).not.toHaveClass('is-go')
    expect(screen.getByTestId('dora')).toHaveClass('is-nak')
  })
})

const alert = (id, extra = {}) => ({
  id, kind: 'pool_full', severity: 'critical', state: 'open', subject: `kea4:subnet:3:pool:192.0.2.${id}-192.0.2.219`, title: `alert ${id}`, details: {},
  node_id: null, first_seen: '2026-10-25T10:00:00Z', last_seen: '2026-10-25T10:00:00Z', ...extra,
})

describe('alerts', () => {
  for (const [level, highlight, folded] of [['full', true, true], ['reduced', true, false], ['off', false, false]]) {
    it(`an opened alert enters its row at ${level}; a resolved one leaves`, async () => {
      db.alerts = [alert('A1')]
      renderAt(level, <AlertsPage />)
      await screen.findByText('alert A1')
      db.alerts = [alert('A2'), alert('A1')]
      publish('alerts', 'opened', db.alerts[0])
      const row = (await screen.findByText('alert A2')).closest('tr')
      expect(row).toHaveAttribute('data-row-phase', 'enter')
      expect(row.classList.contains('is-highlight')).toBe(highlight)
      if (!folded) expect(row).not.toHaveClass('is-folded')
      db.alerts = [alert('A2')]
      publish('alerts', 'resolved', { ...alert('A1'), state: 'resolved' })
      await waitFor(() => expect(screen.queryByText('alert A1')?.closest('tr') ?? null).toHaveAttribute('data-row-phase', 'leave'))
      await waitFor(() => expect(screen.queryByText('alert A1')).toBeNull())
    })
  }
})

const node = (id, name, version, self = false) => ({ peer: { id, name, modules: {}, cert_fingerprint: 'abc' }, is_self: self, status: 'online', version: '0.1.0', config_version: version, audit_count: 10, last_seen: '2026-10-25T10:00:00Z' })

describe('replication', () => {
  it('a replication event moves the peer version: after a pulse at full, at once in reduced', async () => {
    for (const level of ['reduced', 'full']) {
      db.nodes = [node('n1', 'ns1', 43, true), node('n2', 'ns2', 42)]
      db.peers = [{ node_id: 'n2', reachable: true, config_version: 42, audit_count: 10 }]
      const view = renderAt(level, <NodesPage />)
      const peerVersion = () => screen.getByTestId('replication-peer-version').querySelector('.sr-only').textContent
      await screen.findByTestId('replication-link')
      expect(peerVersion()).toBe('42')
      expect(screen.getByTestId('replication-link')).toHaveTextContent('behind by 1 version')
      db.nodes = [node('n1', 'ns1', 43, true), node('n2', 'ns2', 43)]
      db.peers = [{ node_id: 'n2', reachable: true, config_version: 43, audit_count: 10 }]
      publish('system', 'replication', { node_id: 'n2', config_version: 43 })
      if (level === 'reduced') await waitFor(() => expect(peerVersion()).toBe('43'), { timeout: 300 })
      else {
        await waitFor(() => expect(screen.getByTestId('replication-link')).toHaveTextContent('All peers in sync'))
        expect(peerVersion()).toBe('42')
        await waitFor(() => expect(peerVersion()).toBe('43'), { timeout: 1500 })
      }
      view.unmount()
    }
  })
})
