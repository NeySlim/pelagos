// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../services/api'
import { haUpdate, outage, planBlocker, planId, reconcileOffered, stepMessageKey, timeline, wizardStates, wizardStep } from './keaMigration'
import { jobSteps, outputText } from '../../lib/planTrace'

vi.mock('../../services/api', () => {
  const api = { keaMigration: { get: vi.fn(), plan: vi.fn() }, nodes: { list: vi.fn(() => Promise.resolve({ items: [] })) } }
  return { api, default: api }
})
let canHa = true
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => (p === 'ops:dhcp.ha' ? canHa : true) }) }))
// The `ha` and `jobs` handlers the wizard subscribes, called by the tests.
const topics = {}
vi.mock('../../hooks/useWebSocket', async (importOriginal) => ({
  ...(await importOriginal()),
  useWsTopic: (topic, handler) => { if (topic) topics[topic] = handler },
}))
vi.mock('../../components/PlanPreview', () => ({
  PlanPreviewModal: ({ open, plan, title, onClose }) => (open ? (
    <div data-testid="plan-modal" data-plan={plan?.id}>{title}<button type="button" onClick={onClose}>close</button></div>
  ) : null),
}))

const { default: KeaMigrationWizard } = await import('./KeaMigrationWizard')

const analysis = { id: 'A1', series: '3.2', source: 'isc', blocking: false, findings: [] }
const node = (id, name, role, extra = {}) => ({
  node_id: id, name, role, order: role === 'standby' ? 0 : 1, engines: ['kea4', 'd2'], step: null, status: 'pending',
  ha_state: 'hot-standby', from_version: '2.6.3', to_version: '2.6.3', rollback_ready: true, ...extra,
})
const record = (extra = {}) => ({
  id: 'A1', analysis_id: 'A1', series: '3.2', source: 'isc', target_version: '3.2.1-isc20260928103142', from_series: '2.6',
  state: 'prepared', phase: 'prepare', stage: null, plan_id: 'P1', updated_at: '2026-11-02T03:00:00Z',
  outage_started_at: null, outage_seconds: null, outage_max_seconds: 180, rollback_possible: false, error: null, error_step: null,
  nodes: [node('n2', 'ns2', 'standby'), node('n1', 'ns1', 'primary')],
  ...extra,
})

const renderWizard = (props) => render(<MemoryRouter><KeaMigrationWizard analysis={analysis} {...props} /></MemoryRouter>)

describe('wizard helpers', () => {
  it('places the record on its wizard step', () => {
    expect(wizardStep(null)).toBe('prepare')
    expect(wizardStep(record({ state: 'prepare_failed' }))).toBe('prepare')
    expect(wizardStep(record())).toBe('migrate')
    expect(wizardStep(record({ state: 'failed', phase: 'migrate' }))).toBe('migrate')
    expect(wizardStep(record({ state: 'migrated', phase: 'migrate' }))).toBe('verify')
    expect(wizardStep(record({ state: 'rolled_back', phase: 'rollback' }))).toBe('verify')
    expect(wizardStates(record({ state: 'migrating', phase: 'migrate' }))).toEqual({ prepare: 'done', migrate: 'running', verify: 'pending' })
    expect(wizardStates(record({ state: 'prepare_failed' }))).toEqual({ prepare: 'failed', migrate: 'pending', verify: 'pending' })
    expect(wizardStates(record({ state: 'migrated', phase: 'migrate' }))).toEqual({ prepare: 'done', migrate: 'done', verify: 'done' })
  })

  it('draws the times of a migration and of a return', () => {
    const st = (m) => timeline(m).map((s) => `${s.id}:${s.state}`)
    expect(st(record())).toEqual(['standby:pending', 'window:pending', 'primary:pending'])
    expect(st(record({ state: 'migrating', phase: 'migrate', stage: 'window' }))).toEqual(['standby:done', 'window:running', 'primary:pending'])
    expect(st(record({ state: 'failed', phase: 'migrate', stage: 'primary' }))).toEqual(['standby:done', 'window:done', 'primary:failed'])
    expect(st(record({ state: 'migrated', phase: 'migrate', stage: 'done' }))).toEqual(['standby:done', 'window:done', 'primary:done'])
    // Automatic return in the window: time 1 undone, time 2 failed, the return done.
    expect(st(record({ state: 'rolled_back', phase: 'rollback', stage: 'window', error_step: 'kea-mig-wait-partner-down' })))
      .toEqual(['standby:reverted', 'window:failed', 'primary:pending', 'rollback:done'])
    expect(st(record({ state: 'rolling_back', phase: 'rollback', stage: 'done' })))
      .toEqual(['standby:reverted', 'window:reverted', 'primary:reverted', 'rollback:running'])
  })

  it('counts the outage live and keeps the measured one', () => {
    const start = Date.parse('2026-11-02T03:01:00Z')
    expect(outage(record())).toBeNull()
    expect(outage(record({ state: 'migrating', outage_started_at: '2026-11-02T03:01:00Z' }), start + 12500)).toEqual({ seconds: 12.5, live: true })
    expect(outage(record({ state: 'migrated', outage_started_at: '2026-11-02T03:01:00Z', outage_seconds: 21.4 }), start + 99000)).toEqual({ seconds: 21.4, live: false })
    // A stopped migration does not count on.
    expect(outage(record({ state: 'failed', outage_started_at: '2026-11-02T03:01:00Z' }), start + 5000)).toBeNull()
  })

  it('allows the plans the state allows, as the backend', () => {
    expect(planBlocker(null, null, 'prepare')).toBe('noAnalysis')
    expect(planBlocker(null, { ...analysis, blocking: true }, 'prepare')).toBe('blocking')
    expect(planBlocker(null, analysis, 'prepare')).toBeNull()
    expect(planBlocker(record({ state: 'migrating' }), analysis, 'prepare')).toBe('busy')
    expect(planBlocker(record({ state: 'rolled_back' }), analysis, 'prepare')).toBeNull()
    expect(planBlocker(null, analysis, 'migrate')).toBe('noMigration')
    expect(planBlocker(record(), analysis, 'migrate')).toBeNull()
    expect(planBlocker(record({ state: 'failed', phase: 'rollback' }), analysis, 'migrate')).toBe('notPrepared')
    expect(planBlocker(record({ state: 'migrated' }), analysis, 'rollback')).toBe('noRollback')
    expect(planBlocker(record({ state: 'migrated', rollback_possible: true }), analysis, 'rollback')).toBeNull()
    expect(planId(record({ id: 'M' }), analysis, 'prepare')).toBe('A1')
    expect(planId(record({ id: 'M' }), analysis, 'migrate')).toBe('M')
    expect(stepMessageKey('kea-mig-wait-partner-down')).toBe('job.step.kea_migration.wait_partner_down')
    expect(planBlocker(record({ state: 'rolling_back' }), analysis, 'reconcile')).toBe('busy')
    expect(planBlocker(record({ state: 'failed', phase: 'rollback' }), analysis, 'reconcile')).toBeNull()
    expect(reconcileOffered(record())).toBe(true)
    expect(reconcileOffered(record({ state: 'migrated' }))).toBe(false)
    expect(reconcileOffered(record({ state: 'migrating' }))).toBe(false)
  })

  it('turns any step output into text (React error #31)', () => {
    expect(outputText({ record: { status: 'done' }, output: 'ok' })).toBe('ok')
    expect(outputText({ record: { status: 'done' } })).toBe('{"record":{"status":"done"}}')
    expect(outputText(null)).toBe('')
    expect(outputText(3)).toBe('3')
    expect(jobSteps({ steps: [{ name: 's', state: 'done', output: { record: {}, output: 'x' } }] })[0].output).toBe('x')
  })

  it('takes the v4 HA events of the migration nodes only', () => {
    const m = record()
    expect(haUpdate(m, { node_id: 'n2', family: 'v4', state: 'partner-down' })).toEqual({ node_id: 'n2', state: 'partner-down' })
    expect(haUpdate(m, { node_id: 'n2', family: 'v6', state: 'partner-down' })).toBeNull()
    expect(haUpdate(m, { node_id: 'n9', family: 'v4', state: 'x' })).toBeNull()
    expect(haUpdate(null, { node_id: 'n2' })).toBeNull()
  })
})

describe('KeaMigrationWizard', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    canHa = true
    for (const k of Object.keys(topics)) delete topics[k]
  })

  it('builds the prepare plan on the analysis with its options', async () => {
    api.keaMigration.plan.mockResolvedValue({ id: 'P1', scope: 'kea.migration' })
    renderWizard({ current: null })
    expect(screen.getAllByTestId('kea-wizard-step').map((s) => s.dataset.state)).toEqual(['pending', 'pending', 'pending'])
    fireEvent.change(screen.getByTestId('kea-wizard-delay'), { target: { value: '5000' } })
    fireEvent.click(screen.getByTestId('kea-wizard-prepare'))
    expect(await screen.findByTestId('plan-modal')).toHaveTextContent('Prepare the migration to Kea 3.2')
    expect(api.keaMigration.plan).toHaveBeenCalledWith('A1', { phase: 'prepare', options: { response_delay_milliseconds: 5000 } })
  })

  it('refuses to prepare while a blocking finding is open', () => {
    renderWizard({ current: null, analysis: { ...analysis, blocking: true } })
    expect(screen.getByTestId('kea-wizard-prepare')).toBeDisabled()
    expect(screen.getByTestId('kea-wizard-prepare-why')).toHaveTextContent('Fix the blocking findings')
  })

  it('needs ops:dhcp.ha to build a plan', () => {
    canHa = false
    renderWizard({ current: record() })
    expect(screen.getByTestId('kea-wizard-permission')).toBeInTheDocument()
    expect(screen.getByTestId('kea-wizard-migrate')).toBeDisabled()
  })

  it('migrates a prepared pair with the automatic return chosen', async () => {
    api.keaMigration.plan.mockResolvedValue({ id: 'P2', scope: 'kea.migration' })
    renderWizard({ current: record() })
    fireEvent.click(screen.getByTestId('kea-wizard-auto-rollback'))
    fireEvent.click(screen.getByTestId('kea-wizard-migrate'))
    expect(await screen.findByTestId('plan-modal')).toHaveTextContent('Migrate to Kea 3.2')
    expect(api.keaMigration.plan).toHaveBeenCalledWith('A1', { phase: 'migrate', options: { auto_rollback: false } })
    expect(screen.queryByTestId('kea-wizard-rollback')).not.toBeInTheDocument()
  })

  it('shows the window live: timeline, HA events, outage, then the measured outage', async () => {
    const running = record({
      state: 'migrating', phase: 'migrate', stage: 'window', outage_started_at: new Date(Date.now() - 4000).toISOString(), rollback_possible: true,
      nodes: [node('n2', 'ns2', 'standby', { step: 'kea-mig-start', status: 'running', to_version: '3.2.1' }), node('n1', 'ns1', 'primary', { step: 'kea-mig-stop', status: 'done' })],
    })
    api.keaMigration.get.mockResolvedValue({ ...running, stage: 'primary', outage_seconds: 6.2 })
    renderWizard({ current: running })
    expect(screen.getAllByTestId('kea-wizard-time-step').map((s) => s.dataset.state)).toEqual(['done', 'running', 'pending'])
    expect(screen.getByTestId('kea-wizard-outage')).toHaveAttribute('data-live', 'true')
    expect(screen.getByTestId('kea-wizard-outage-value')).toHaveTextContent(/DHCP outage running: [4-9]\.\d s/)
    const rows = screen.getAllByTestId('kea-wizard-node')
    expect(rows[0]).toHaveTextContent('ns2: start Kea')
    expect(within(rows[0]).getByTestId('kea-wizard-version')).toHaveTextContent('2.6.3 > 3.2.1')
    act(() => topics.ha({ data: { node_id: 'n2', family: 'v4', state: 'partner-down' } }))
    expect(within(rows[0]).getByTestId('kea-wizard-ha')).toHaveTextContent('partner-down')
    expect(screen.getByTestId('kea-wizard-rollback')).toBeEnabled()
    // A job event of the migration's plan reads the record again.
    await act(async () => topics.jobs({ data: { plan_id: 'P1', state: 'running' } }))
    await waitFor(() => expect(screen.getByTestId('kea-wizard-outage-value')).toHaveTextContent('Measured DHCP outage: 6.2 s'))
    expect(api.keaMigration.get).toHaveBeenCalledWith('A1')
  })

  it('shows an automatic return with its error and offers to prepare again', () => {
    renderWizard({ current: record({ state: 'rolled_back', phase: 'rollback', stage: 'window', error: 'no partner-down within 180 s', error_step: 'kea-mig-wait-partner-down' }) })
    expect(screen.getByTestId('kea-wizard-verify')).toHaveTextContent('back on Kea 2.6')
    expect(screen.getByTestId('kea-wizard-error')).toHaveTextContent('kea-mig-wait-partner-down: no partner-down within 180 s')
    expect(screen.getAllByTestId('kea-wizard-time-step').map((s) => s.dataset.state)).toEqual(['reverted', 'failed', 'pending', 'done'])
    expect(screen.getByTestId('kea-wizard-prepare')).toHaveTextContent('Prepare again')
    expect(screen.queryByTestId('kea-wizard-prepare-again')).toBeNull()
  })

  it('tells to prepare again when the kept package files went away', () => {
    const error = '/var/lib/pelagos-helper/kea-migration/A1/packages/target/x.deb is missing: prepare this node again'
    renderWizard({ current: record({ state: 'failed', phase: 'migrate', stage: 'standby', error, error_step: 'kea-mig-stop' }) })
    expect(screen.getByTestId('kea-wizard-prepare-again')).toHaveTextContent('prepare the migration again')
  })

  it('renders error objects as text and offers to read the real state back', async () => {
    api.keaMigration.plan.mockResolvedValue({ id: 'P4', scope: 'kea.migration' })
    const failed = record({
      state: 'failed', phase: 'rollback', stage: 'standby', error_step: 'kea-mig-install',
      error: { record: { status: 'failed' }, output: 'previous packages not installed' },
      nodes: [node('n2', 'ns2', 'standby', { status: 'failed', error: { record: {}, output: 'E: Unable to fetch some archives' } }), node('n1', 'ns1', 'primary')],
    })
    renderWizard({ current: failed })
    expect(screen.getByTestId('kea-wizard-error')).toHaveTextContent('kea-mig-install: previous packages not installed')
    expect(screen.getAllByTestId('kea-wizard-node')[0]).toHaveTextContent('E: Unable to fetch some archives')
    fireEvent.click(screen.getByTestId('kea-wizard-reconcile'))
    expect(await screen.findByTestId('plan-modal')).toHaveTextContent('Check the real state, mark as back on Kea 2.6')
    expect(api.keaMigration.plan).toHaveBeenCalledWith('A1', { phase: 'reconcile', options: {} })
  })

  it('says when the real state was read back', () => {
    renderWizard({ current: record({ state: 'rolled_back', phase: 'reconcile' }) })
    expect(screen.getByTestId('kea-wizard-verify')).toHaveTextContent('The real state was read back')
  })

  it('offers the return of a migrated pair while it is possible', async () => {
    api.keaMigration.plan.mockResolvedValue({ id: 'P3', scope: 'kea.migration' })
    renderWizard({ current: record({ state: 'migrated', phase: 'migrate', stage: 'done', outage_seconds: 21.4, rollback_possible: true }) })
    expect(screen.getByTestId('kea-wizard-verify')).toHaveTextContent('Every node runs Kea 3.2')
    expect(screen.getByTestId('kea-wizard-outage-value')).toHaveTextContent('21.4 s')
    fireEvent.click(screen.getByTestId('kea-wizard-rollback'))
    expect(await screen.findByTestId('plan-modal')).toHaveTextContent('Return to Kea 2.6')
    expect(api.keaMigration.plan).toHaveBeenCalledWith('A1', { phase: 'rollback', options: {} })
  })
})
