// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within, renderHook, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../../services/api'
import { resources, languages } from '../../../i18n'

vi.mock('../../../services/api', () => {
  const api = {
    updates: { overview: vi.fn(), check: vi.fn(), upload: vi.fn(), saveSettings: vi.fn(), plan: vi.fn(), rollout: vi.fn(), action: vi.fn(), history: vi.fn() },
    plans: { apply: vi.fn(), rollback: vi.fn(), get: vi.fn() },
    jobs: { get: vi.fn() },
    meta: { health: vi.fn() },
    nodes: { list: vi.fn(async () => ({ items: [] })) },
  }
  return { api, default: api }
})
vi.mock('../../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))

const { default: UpdatesPage } = await import('./UpdatesPage')
const { useRolloutWatch } = await import('./useRolloutWatch')

const NODES = [
  { node_id: 'n1', name: 'ns1', version: '0.2.4', arch: 'amd64', package_format: 'deb', previous_kept: null, state_schema: 1, reachable: true },
  { node_id: 'n2', name: 'ns2', version: '0.2.4', arch: 'arm64', package_format: 'deb', previous_kept: null, state_schema: 1, reachable: true },
]
const RELEASE = { version: '0.3.0', source: 'github', published_at: '2026-10-28T10:00:00Z', notes: '# Pelagos 0.3.0\n\n- Updates from the UI', signature: 'valid', signed: true, key_id: 'a1b2c3d4e5f60718', state_schema: 1, min_upgrade_from: '0.2.4' }
const ENGINES = [
  { node_id: 'n1', engine: 'bind', package: 'bind9', installed: '1:9.20.11-4', candidate: '1:9.20.15-1~deb13u1', cves: ['CVE-2025-40778'] },
  { node_id: 'n1', engine: 'kea4', package: 'kea-dhcp4-server', installed: '2.6.3-1', candidate: null, cves: [] },
]
const SETTINGS = { source: 'github', check_enabled: true, check_interval_hours: 24, settle_seconds: 30, timeout_seconds: 300, pause_seconds: 60, auto_rollback_enabled: true, keep_packages_count: 2, github_repository: 'example/pelagos', github_token_stored: false }
const overview = (over = {}) => ({ nodes: NODES, available: [RELEASE], rollout: null, settings: SETTINGS, engines: ENGINES, checked_at: '2026-10-30T08:00:00Z', docker: null, ...over })
const rolloutNode = (id, over = {}) => ({ node_id: id, state: 'pending', step: null, started_at: null, finished_at: null, error: null, error_message: null, from_version: '0.2.4', to_version: '0.3.0', ...over })
const ROLLOUT = { id: 'r1', kind: 'pelagos', version: '0.3.0', state: 'running', order: ['n2', 'n1'], nodes: [rolloutNode('n2', { state: 'running', step: 'install' }), rolloutNode('n1')], created_by: 'admin', created_at: '2026-10-30T09:00:00Z', packages: {}, auto_rollback: true, state_schema_changed: false }
const PLAN = (update = {}) => ({
  id: 'p1', scope: 'update', engine: null, state: 'validated', requires_confirmation: true, summary: 'update Pelagos to 0.3.0 on ns2, ns1, in this order', summary_message: null,
  changes: [], validations: [], created_by: 'admin', created_at: '2026-10-30T09:00:00Z', expires_at: new Date(Date.now() + 600000).toISOString(), target_node_ids: ['n2', 'n1'],
  update: { kind: 'pelagos', version: '0.3.0', order: ['n2', 'n1'], signature: 'valid', key_id: RELEASE.key_id, unsigned_warning: null, state_schema_changed: false, auto_rollback: true, checks: ['precheck', 'backup', 'health'], estimated_seconds: 300, requires_password: true, ...update },
})

const renderPage = () => render(<MemoryRouter><UpdatesPage /></MemoryRouter>)

describe('UpdatesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.updates.overview.mockResolvedValue(overview())
    api.updates.history.mockResolvedValue({ items: [], total: 0, page: 1, per_page: 20 })
    api.updates.rollout.mockResolvedValue(null)
  })

  it('shows the nodes, the release with its signature and notes, and applies the plan with the password', async () => {
    api.updates.plan.mockResolvedValue(PLAN())
    api.plans.apply.mockResolvedValue({ plan_id: 'p1', state: 'applied', results: [] })
    renderPage()
    const release = await screen.findByTestId('updates-release')
    expect(within(release).getByTestId('updates-signature')).toHaveAttribute('data-signature', 'valid')
    expect(release).toHaveTextContent('ns1, ns2')
    expect(screen.getByTestId('updates-no-previous')).toBeInTheDocument()
    fireEvent.click(within(release).getByTestId('updates-notes-toggle'))
    expect(within(release).getByTestId('updates-notes')).toHaveTextContent('Updates from the UI')

    fireEvent.click(within(release).getByTestId('updates-prepare'))
    const preview = await screen.findByTestId('updates-preview')
    await waitFor(() => expect(api.updates.plan).toHaveBeenCalledWith({ kind: 'pelagos', version: '0.3.0', auto_rollback: true }))
    const order = await within(preview).findAllByTestId('updates-order-node')
    expect(order.map((li) => li.dataset.node)).toEqual(['n2', 'n1'])
    expect(within(preview).getByTestId('updates-estimate')).toHaveTextContent('5 min')

    // Reordering makes the plan stale until it is computed again with the new order.
    fireEvent.click(within(order[1]).getByTestId('updates-order-up'))
    expect(within(preview).getByTestId('updates-stale')).toBeInTheDocument()
    api.updates.plan.mockResolvedValue(PLAN({ order: ['n1', 'n2'] }))
    fireEvent.click(within(preview).getByTestId('updates-recompute'))
    await waitFor(() => expect(api.updates.plan).toHaveBeenLastCalledWith({ kind: 'pelagos', version: '0.3.0', auto_rollback: true, order: ['n1', 'n2'] }))

    const box = await within(preview).findByRole('checkbox')
    fireEvent.click(box)
    api.updates.overview.mockResolvedValue(overview({ rollout: ROLLOUT }))
    fireEvent.change(within(preview).getByTestId('updates-password'), { target: { value: 'secret' } })
    fireEvent.click(within(preview).getByRole('button', { name: /apply/i }))
    await waitFor(() => expect(api.plans.apply).toHaveBeenCalledWith('p1', true, { password: 'secret' }))
    const panel = await screen.findByTestId('updates-rollout')
    expect(panel).toHaveAttribute('data-state', 'running')
    expect(within(panel).getAllByTestId('updates-rollout-node')[0]).toHaveAttribute('data-step', 'install')
    expect(screen.getByTestId('updates-prepare')).toBeDisabled()
  })

  it('asks the extra confirmation of an unsigned release before any plan', async () => {
    api.updates.overview.mockResolvedValue(overview({ available: [{ ...RELEASE, version: '0.3.1', signature: 'unsigned', signed: false, key_id: null }] }))
    api.updates.plan.mockResolvedValue(PLAN({ version: '0.3.1', signature: 'unsigned', unsigned_warning: { key: 'plan.update.unsigned', params: { version: '0.3.1' } } }))
    renderPage()
    fireEvent.click(await screen.findByTestId('updates-prepare'))
    const warning = await screen.findByTestId('updates-unsigned')
    expect(warning).toHaveTextContent('0.3.1 is not signed: its origin is not verified')
    const go = within(warning).getByTestId('updates-unsigned-continue')
    expect(go).toBeDisabled()
    expect(api.updates.plan).not.toHaveBeenCalled()
    fireEvent.click(within(warning).getByTestId('updates-unsigned-accept'))
    fireEvent.change(within(warning).getByTestId('updates-unsigned-version'), { target: { value: '0.3' } })
    expect(go).toBeDisabled()
    fireEvent.change(within(warning).getByTestId('updates-unsigned-version'), { target: { value: '0.3.1' } })
    fireEvent.click(go)
    await waitFor(() => expect(api.updates.plan).toHaveBeenCalledWith({ kind: 'pelagos', version: '0.3.1', auto_rollback: true, accept_unsigned: true, confirm_version: '0.3.1' }))
  })

  it('shows a stopped rollout with its reason and resumes it', async () => {
    const failed = { ...ROLLOUT, state: 'failed', nodes: [rolloutNode('n2', { state: 'done', to_version: '0.3.0' }), rolloutNode('n1', { state: 'rolled_back', step: 'health', error: 'no health answer', to_version: '0.2.4' })] }
    api.updates.overview.mockResolvedValue(overview({ rollout: failed }))
    api.updates.rollout.mockResolvedValue(failed)
    api.updates.action.mockResolvedValue({ ...failed, state: 'running' })
    renderPage()
    const panel = await screen.findByTestId('updates-rollout')
    expect(within(panel).getByTestId('updates-rollout-error')).toHaveTextContent('Health: no health answer')
    expect(within(panel).getByTestId('updates-rollout-failed')).toHaveTextContent('went back to its previous package automatically')
    expect(within(panel).getByTestId('updates-rollback')).toBeInTheDocument()
    fireEvent.click(within(panel).getByTestId('updates-resume'))
    await waitFor(() => expect(api.updates.action).toHaveBeenCalledWith('r1', 'resume', undefined))
    await waitFor(() => expect(screen.getByTestId('updates-rollout')).toHaveAttribute('data-state', 'running'))
  })

  it('updates engine packages from the selection', async () => {
    api.updates.plan.mockResolvedValue(PLAN({ kind: 'engine_packages', version: null, packages: { bind9: '1:9.20.15-1~deb13u1' } }))
    renderPage()
    await screen.findByTestId('updates-release')
    fireEvent.click(screen.getByRole('button', { name: 'Engine packages' }))
    const table = await screen.findByTestId('updates-engines')
    expect(table).toHaveTextContent('CVE-2025-40778')
    expect(within(table).getAllByTestId('updates-engine-pick')).toHaveLength(1)
    fireEvent.click(within(table).getByTestId('updates-engine-pick'))
    fireEvent.click(within(table).getByTestId('updates-engines-update'))
    await waitFor(() => expect(api.updates.plan).toHaveBeenCalledWith({ kind: 'engine_packages', packages: ['bind9'], node_ids: ['n1'], auto_rollback: true }))
  })

  it('opens the engine packages picked by a security advisory link', async () => {
    api.updates.plan.mockResolvedValue(PLAN({ kind: 'engine_packages', version: null, packages: { bind9: '1:9.20.15-1~deb13u1' } }))
    render(<MemoryRouter initialEntries={['/admin/updates?tab=engines&package=bind9&node=n1']}><UpdatesPage /></MemoryRouter>)
    const table = await screen.findByTestId('updates-engines')
    expect(within(table).getByTestId('updates-engine-pick')).toBeChecked()
    fireEvent.click(within(table).getByTestId('updates-engines-update'))
    await waitFor(() => expect(api.updates.plan).toHaveBeenCalledWith({ kind: 'engine_packages', packages: ['bind9'], node_ids: ['n1'], auto_rollback: true }))
  })
})

describe('useRolloutWatch', () => {
  afterEach(() => vi.clearAllMocks())

  it('waits for /health while the node restarts, then reads the rollout again', async () => {
    const onReconnected = vi.fn()
    const onFinished = vi.fn()
    api.updates.rollout.mockRejectedValueOnce(Object.assign(new Error('Network error'), { status: 0, code: 'network_error' }))
    api.meta.health.mockRejectedValue(new Error('down'))
    const { result } = renderHook(() => useRolloutWatch(ROLLOUT, { onReconnected, onFinished, pollMs: 15 }))
    await waitFor(() => expect(result.current.connection).toBe('lost'))
    api.updates.rollout.mockResolvedValue({ ...ROLLOUT, nodes: ROLLOUT.nodes.map((n) => ({ ...n, state: 'done', step: null })), state: 'done' })
    api.meta.health.mockResolvedValue({ status: 'ok' })
    await waitFor(() => expect(onReconnected).toHaveBeenCalled())
    expect(api.meta.health).toHaveBeenCalled()
    await waitFor(() => expect(onFinished).toHaveBeenCalled())
    await waitFor(() => expect(result.current.connection).toBe('ok'))
    expect(result.current.rollout.state).toBe('done')
  })

  it('reads the final state from the history when the rollout left updates.rollout', async () => {
    const onFinished = vi.fn()
    api.updates.rollout.mockResolvedValue(null)
    api.updates.history.mockResolvedValue({ items: [{ id: 'r1', state: 'done', nodes: [{ node_id: 'n2', state: 'done' }, { node_id: 'n1', state: 'done' }] }] })
    const { result } = renderHook(() => useRolloutWatch(ROLLOUT, { onFinished, pollMs: 15 }))
    await waitFor(() => expect(onFinished).toHaveBeenCalled())
    expect(result.current.rollout.state).toBe('done')
    expect(result.current.rollout.nodes.every((n) => n.state === 'done')).toBe(true)
    await act(async () => {})
  })
})

describe('updates i18n', () => {
  const sources = import.meta.glob(['./*.{js,jsx}', '!./*.test.*'], { eager: true, query: '?raw', import: 'default' })
  const flat = (o, p = '') => Object.entries(o).flatMap(([k, v]) => (v && typeof v === 'object' ? flat(v, `${p}${k}.`) : [`${p}${k}`]))
  const resolve = (lang, ns, key) => {
    const get = (k) => k.split('.').reduce((o, x) => (o == null ? undefined : o[x]), resources[lang][ns])
    return get(key) ?? get(`${key}_other`)
  }

  it('has the same keys in every language', () => {
    const ref = flat(resources.en.updates).sort()
    for (const { code } of languages) expect(flat(resources[code].updates).sort()).toEqual(ref)
  })

  it('resolves every literal key the screen uses', () => {
    let n = 0
    for (const [file, text] of Object.entries(sources)) {
      for (const m of text.matchAll(/\bt\(\s*'([A-Za-z0-9_.:-]+)'/g)) {
        const [ns, key] = m[1].includes(':') ? m[1].split(':') : ['updates', m[1]]
        for (const { code } of languages) expect(resolve(code, ns, key), `${file} ${code} ${m[1]}`).toBeTypeOf('string')
        n += 1
      }
    }
    expect(n).toBeGreaterThan(50)
  })
})
