// SPDX-License-Identifier: Apache-2.0
// Partial apply in PlanPreview (section 6, B1-KEAOFFLINE).
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import '../i18n'
import { PlanPreview } from './PlanPreview'

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

  it.todo('a 409 reconcile_required names the nodes and the source to reconcile from')
})

describe('Alerts reconcile action', () => {
  it.todo('a config_divergence alert with details.reconcile offers "Reconcile from <node>"')
  it.todo('both directions are offered when both sides changed')
  it.todo('the action builds POST /dhcp/{family}/config/reconcile/plan and opens the plan preview')
  it.todo('without write:dhcp.config the action is replaced by a read-only note')
})
