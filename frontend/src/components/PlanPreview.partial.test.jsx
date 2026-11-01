// SPDX-License-Identifier: Apache-2.0
// Partial apply in PlanPreview (section 6, B1-KEAOFFLINE).
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '../i18n'
import { PlanPreview } from './PlanPreview'
import { ReconcileActions } from '../pages/alerts/ReconcileActions'

const reconcilePlan = vi.fn()
let canWrite = true
vi.mock('../services/api', () => {
  const api = {
    dhcp: { reconcilePlan: (...a) => reconcilePlan(...a) },
    nodes: { list: async () => ({ items: [{ peer: { id: 'n1', name: 'ns1' }, is_self: true }, { peer: { id: 'n2', name: 'ns2' }, is_self: false }] }) },
  }
  return { api, default: api }
})
vi.mock('../contexts/NotificationContext', () => ({ useNotification: () => ({ showError: vi.fn(), showSuccess: vi.fn(), showInfo: vi.fn() }) }))
vi.mock('../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => canWrite }) }))

const NAMES = { n1: 'ns1', n2: 'ns2' }
const nodeName = (id) => NAMES[id] || id

function makePlan(overrides = {}) {
  return {
    id: '01JBPLAN0000000000000000KA',
    created_at: '2026-11-01T10:00:00Z',
    created_by: 'alice',
    node_id: 'n1',
    scope: 'dhcp.reservation',
    engine: 'kea4',
    summary: 'add reservation',
    changes: [{ op: 'add', target: 'subnet4/1/reservations/hw-address=aa:bb:cc:dd:ee:ff', before: null, after: {}, node_ids: [] }],
    diff: '+reservation\n',
    preconditions: [],
    validations: [],
    target_node_ids: ['n1', 'n2'],
    requires_confirmation: false,
    requires_confirmation_reasons: [],
    state: 'validated',
    expires_at: new Date(Date.now() + 600000).toISOString(),
    error: null,
    ...overrides,
  }
}

const offline = (reason = 'unreachable', allowed = true) =>
  Object.assign(new Error('A target node is offline'), {
    code: 'node_unreachable',
    status: 409,
    problem: { node_ids: ['n2'], node_names: ['ns2'], partial_allowed: allowed, nodes: [{ node_id: 'n2', reason }] },
  })

const appliedPartial = {
  plan_id: '01JBPLAN0000000000000000KA',
  state: 'applied',
  results: [{ node_id: 'n1', ok: true, message: 'ok', rolled_back: false, audit_ids: [] }],
  finished_at: '2026-11-01T10:00:05Z',
}

describe('PlanPreview partial apply', () => {
  it('a 409 node_unreachable with partial_allowed shows the box, asks for confirmation, then applies in part', async () => {
    const applyFn = vi.fn().mockRejectedValueOnce(offline()).mockResolvedValueOnce(appliedPartial)
    const getFn = vi.fn().mockResolvedValue(makePlan({ state: 'applied', partial: true, skipped: [{ node_id: 'n2', reason: 'unreachable' }] }))
    render(<PlanPreview plan={makePlan()} applyFn={applyFn} getFn={getFn} nodeName={nodeName} />)
    expect(screen.queryByTestId('plan-partial-checkbox')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-partial-checkbox')).toBeInTheDocument())
    expect(applyFn).toHaveBeenCalledWith('01JBPLAN0000000000000000KA', false)
    expect(screen.getByTestId('plan-footer')).toHaveTextContent('Apply only on the reachable nodes (ns2 offline)')
    fireEvent.click(screen.getByTestId('plan-partial-checkbox'))
    expect(screen.getByTestId('plan-confirm-reasons')).toHaveTextContent('the plan is applied on part of its nodes')
    expect(screen.getByTestId('plan-apply')).toBeDisabled()
    fireEvent.click(screen.getByTestId('plan-confirm-checkbox'))
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(applyFn).toHaveBeenLastCalledWith('01JBPLAN0000000000000000KA', true, { partial: true }))
    await waitFor(() => expect(screen.getByTestId('plan-skipped')).toHaveTextContent('ns2'))
    expect(screen.getByTestId('plan-skipped')).toHaveTextContent('skipped: offline')
  })

  it('a partner still in touch shows the explanation and no box', async () => {
    render(<PlanPreview plan={makePlan()} applyFn={vi.fn().mockRejectedValue(offline('ha_partner_in_touch', false))} nodeName={nodeName} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-partner-in-touch')).toHaveTextContent('The Pelagos service of ns2 does not answer'))
    expect(screen.queryByTestId('plan-partial-checkbox')).not.toBeInTheDocument()
  })

  it('a controlled partialOption from the caller wins over the internal box', async () => {
    const onChange = vi.fn()
    const applyFn = vi.fn().mockRejectedValue(offline())
    render(<PlanPreview plan={makePlan()} applyFn={applyFn} partialOption={{ checked: false, onChange, nodeIds: ['n1'] }} nodeName={nodeName} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-apply-error')).toBeInTheDocument())
    expect(screen.getAllByTestId('plan-partial-checkbox')).toHaveLength(1)
    expect(screen.getByTestId('plan-footer')).toHaveTextContent('(ns1 offline)')
    fireEvent.click(screen.getByTestId('plan-partial-checkbox'))
    expect(onChange).toHaveBeenCalledWith(true)
  })

  it('a plan that already needs confirmation keeps its own reasons next to partial_apply', async () => {
    const applyFn = vi.fn().mockRejectedValue(offline())
    render(<PlanPreview plan={makePlan({ requires_confirmation: true, requires_confirmation_reasons: ['delete'] })} applyFn={applyFn} nodeName={nodeName} />)
    fireEvent.click(screen.getByTestId('plan-confirm-checkbox'))
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-partial-checkbox')).toBeInTheDocument())
    fireEvent.click(screen.getByTestId('plan-partial-checkbox'))
    expect(screen.getByTestId('plan-confirm-reasons')).toHaveTextContent('a configuration object is deleted, the plan is applied on part of its nodes')
  })

  it('a 409 reconcile_required names the nodes and the source to reconcile from', async () => {
    const err = Object.assign(new Error('ns2 missed a partial apply'), {
      code: 'reconcile_required',
      status: 409,
      problem: { engine: 'kea4', divergences: [{ node_id: 'n2', node_name: 'ns2', source_node_id: 'n1', plan_ids: [], since: null }] },
    })
    render(<PlanPreview plan={makePlan()} applyFn={vi.fn().mockRejectedValue(err)} nodeName={nodeName} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    const note = await screen.findByTestId('plan-reconcile-required')
    expect(note).toHaveTextContent('ns2 missed a partial apply: reconcile it from ns1 first')
  })
})

const alertOf = (reconcile, extra = {}) => ({
  id: 'A1',
  kind: 'config_divergence',
  engine: 'kea4',
  subject: 'kea4:config-hash',
  state: 'open',
  details: { reconcile },
  ...extra,
})
const reconcileOf = (source, target) => ({
  ...makePlan({ scope: 'dhcp.config', requires_confirmation: true, requires_confirmation_reasons: ['reconcile'], target_node_ids: [target] }),
  summary: `kea4: reconcile ${nodeName(target)} from ${nodeName(source)}`,
  impact: [
    { kind: 'reconcile_overwrites', severity: 'warning', text: 'ns2 changed too: 2 differences are overwritten (plans P1)', count: 0, examples: [] },
    { kind: 'reconcile_residual', severity: 'warning', text: '1 differences stay after the copy', count: 0, examples: [] },
    { kind: 'ha_restart', severity: 'warning', text: 'ns2 reloads Kea: its HA service restarts in waiting', count: 0, examples: [] },
  ],
})

describe('Alerts reconcile action', () => {
  beforeEach(() => {
    canWrite = true
    reconcilePlan.mockReset()
  })

  it('a config_divergence alert with details.reconcile offers "Reconcile from <node>"', async () => {
    render(<ReconcileActions alert={alertOf([{ source_node_id: 'n1', target_node_id: 'n2' }])} />)
    expect(await screen.findByRole('button', { name: 'Reconcile from ns1' })).toBeInTheDocument()
    expect(screen.getAllByTestId('alert-reconcile')).toHaveLength(1)
  })

  it('does nothing for an alert without details.reconcile or a resolved one', () => {
    const { container, rerender } = render(<ReconcileActions alert={alertOf(undefined)} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<ReconcileActions alert={alertOf([{ source_node_id: 'n1', target_node_id: 'n2' }], { state: 'resolved' })} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('both directions are offered when both sides changed', async () => {
    render(<ReconcileActions alert={alertOf([{ source_node_id: 'n1', target_node_id: 'n2' }, { source_node_id: 'n2', target_node_id: 'n1' }])} />)
    await screen.findByRole('button', { name: 'Reconcile from ns1' })
    expect(screen.getByRole('button', { name: 'Reconcile from ns2' })).toBeInTheDocument()
  })

  it('the action builds POST /dhcp/{family}/config/reconcile/plan and opens the plan preview', async () => {
    reconcilePlan.mockResolvedValue(reconcileOf('n1', 'n2'))
    render(<ReconcileActions alert={alertOf([{ source_node_id: 'n1', target_node_id: 'n2' }])} />)
    fireEvent.click(await screen.findByTestId('alert-reconcile'))
    await waitFor(() => expect(reconcilePlan).toHaveBeenCalledWith('v4', 'n1', 'n2'))
    const preview = await screen.findByTestId('plan-preview')
    expect(preview).toHaveTextContent('kea4: reconcile ns2 from ns1')
    expect(screen.getByTestId('plan-confirm-reasons')).toHaveTextContent('the configuration of a node is replaced')
    expect(screen.getByTestId('plan-impact')).toHaveTextContent('differences are overwritten')
    expect(screen.getByTestId('plan-impact')).toHaveTextContent('HA service restarts')
  })

  it('without write:dhcp.config the action is replaced by a read-only note', () => {
    canWrite = false
    render(<ReconcileActions alert={alertOf([{ source_node_id: 'n1', target_node_id: 'n2' }])} />)
    expect(screen.queryByTestId('alert-reconcile')).not.toBeInTheDocument()
    expect(screen.getByTestId('read-only-note')).toHaveTextContent('write:dhcp.config')
  })
})
