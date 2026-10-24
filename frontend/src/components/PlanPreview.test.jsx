// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { PlanPreview } from './PlanPreview'

function makePlan(overrides = {}) {
  return {
    id: '01JBPLAN0000000000000000AA',
    created_at: '2026-10-24T10:00:00Z',
    created_by: 'alice',
    node_id: 'n1',
    scope: 'dns.rrset',
    engine: 'bind',
    summary: '1 change(s) in example.lan.',
    changes: [{ op: 'add', target: 'example.lan./www.example.lan./A', before: null, after: { rdata: ['192.0.2.80'] }, node_ids: [] }],
    diff: '--- a/example.lan.\n+++ b/example.lan.\n@@ -1,0 +1,1 @@\n+www.example.lan. 300 IN A 192.0.2.80\n',
    preconditions: [{ kind: 'soa_serial', node_id: 'n1', subject: 'example.lan.', value: '2026102401' }],
    validations: [{ ok: true, tool: 'dnspython', output: '', node_id: 'n1' }],
    target_node_ids: ['n1', 'n2'],
    requires_confirmation: false,
    state: 'validated',
    expires_at: new Date(Date.now() + 600000).toISOString(),
    error: null,
    ...overrides,
  }
}

const applied = (state = 'applied') => ({
  plan_id: '01JBPLAN0000000000000000AA',
  state,
  results: [
    { node_id: 'n1', ok: true, message: 'NOERROR', rolled_back: false, audit_ids: ['x'] },
    { node_id: 'n2', ok: true, message: 'NOERROR', rolled_back: state === 'rolled_back', audit_ids: ['y'] },
  ],
  finished_at: '2026-10-24T10:00:05Z',
})

describe('PlanPreview', () => {
  it('shows summary, changes, diff and validations', () => {
    render(<PlanPreview plan={makePlan()} />)
    expect(screen.getByTestId('plan-summary')).toHaveTextContent('1 change(s) in example.lan.')
    expect(screen.getByTestId('plan-changes')).toHaveTextContent('example.lan./www.example.lan./A')
    expect(screen.getByTestId('plan-diff')).toHaveTextContent('www.example.lan. 300 IN A 192.0.2.80')
    expect(screen.getByText('DNS records')).toBeInTheDocument()
    expect(screen.getByTestId('plan-apply')).toBeEnabled()
  })

  it('applies, shows the per-node result, then rolls back', async () => {
    const applyFn = vi.fn().mockResolvedValue(applied())
    const rollbackFn = vi.fn().mockResolvedValue(applied('rolled_back'))
    const onApplied = vi.fn()
    render(<PlanPreview plan={makePlan()} applyFn={applyFn} rollbackFn={rollbackFn} onApplied={onApplied} getFn={vi.fn().mockResolvedValue(makePlan({ state: 'applied' }))} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-result')).toBeInTheDocument())
    expect(applyFn).toHaveBeenCalledWith('01JBPLAN0000000000000000AA', false)
    expect(onApplied).toHaveBeenCalled()
    expect(screen.queryByTestId('plan-apply')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('plan-rollback'))
    await waitFor(() => expect(rollbackFn).toHaveBeenCalledWith('01JBPLAN0000000000000000AA'))
    await waitFor(() => expect(screen.queryByTestId('plan-rollback')).not.toBeInTheDocument())
  })

  it('keeps rollback available for the TTL restarted at apply', async () => {
    const getFn = vi.fn().mockResolvedValue(makePlan({ state: 'applied', expires_at: new Date(Date.now() + 600000).toISOString() }))
    render(<PlanPreview plan={makePlan({ expires_at: new Date(Date.now() + 1200).toISOString() })} applyFn={vi.fn().mockResolvedValue(applied())} getFn={getFn} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(getFn).toHaveBeenCalledWith('01JBPLAN0000000000000000AA'))
    await act(() => new Promise((resolve) => setTimeout(resolve, 2100)))
    expect(screen.getByTestId('plan-rollback')).toBeInTheDocument()
  })

  it('requires the confirmation checkbox when the plan asks for it', async () => {
    const applyFn = vi.fn().mockResolvedValue(applied())
    render(<PlanPreview plan={makePlan({ scope: 'dhcp.ha', requires_confirmation: true })} applyFn={applyFn} />)
    const button = screen.getByTestId('plan-apply')
    expect(button).toBeDisabled()
    fireEvent.click(screen.getByTestId('plan-confirm-checkbox'))
    expect(button).toBeEnabled()
    fireEvent.click(button)
    await waitFor(() => expect(applyFn).toHaveBeenCalledWith('01JBPLAN0000000000000000AA', true))
  })

  it('blocks apply for failed validation and shows the tool output', () => {
    const plan = makePlan({ state: 'failed', error: 'Validation failed', validations: [{ ok: false, tool: 'named-checkconf', output: 'zones.conf:3: unknown option', node_id: 'n1' }] })
    render(<PlanPreview plan={plan} />)
    expect(screen.getByTestId('plan-apply')).toBeDisabled()
    expect(screen.getByTestId('plan-validations')).toHaveTextContent('zones.conf:3: unknown option')
    expect(screen.getByTestId('plan-error')).toHaveTextContent('Validation failed')
  })

  it('blocks apply once the plan has expired', () => {
    render(<PlanPreview plan={makePlan({ expires_at: new Date(Date.now() - 1000).toISOString() })} />)
    expect(screen.getByTestId('plan-apply')).toBeDisabled()
    expect(screen.getByText('Expired')).toBeInTheDocument()
  })

  it('shows engine validation errors returned by apply', async () => {
    const err = Object.assign(new Error('The engine rejected the configuration'), {
      code: 'engine_validation_failed',
      errors: [{ message: "named.conf:14: unknown option 'forwarder'" }],
    })
    render(<PlanPreview plan={makePlan()} applyFn={vi.fn().mockRejectedValue(err)} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-apply-error')).toHaveTextContent("unknown option 'forwarder'"))
  })

  it('offers to recompute a plan the server answered 410 for', async () => {
    const err = Object.assign(new Error('plan expired'), { code: 'plan_expired', status: 410 })
    const fresh = makePlan({ id: '01JBPLAN0000000000000000BB', summary: 'rebuilt' })
    const onRecompute = vi.fn().mockResolvedValue(fresh)
    const applyFn = vi.fn().mockRejectedValueOnce(err).mockResolvedValueOnce(applied())
    render(<PlanPreview plan={makePlan()} applyFn={applyFn} onRecompute={onRecompute} getFn={vi.fn().mockResolvedValue(fresh)} />)
    expect(screen.queryByTestId('plan-recompute')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-recompute')).toBeInTheDocument())
    expect(screen.getByTestId('plan-gone')).toHaveTextContent('Recompute it from the same inputs')
    fireEvent.click(screen.getByTestId('plan-recompute'))
    await waitFor(() => expect(screen.getByTestId('plan-summary')).toHaveTextContent('rebuilt'))
    expect(onRecompute).toHaveBeenCalledTimes(1)
    expect(screen.queryByTestId('plan-recompute')).not.toBeInTheDocument()
    expect(screen.queryByTestId('plan-apply-error')).not.toBeInTheDocument()
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(applyFn).toHaveBeenLastCalledWith('01JBPLAN0000000000000000BB', false))
  })

  it('offers to recompute after a restart (404) and when the countdown ran out', async () => {
    const lost = Object.assign(new Error('not found'), { code: 'not_found', status: 404 })
    const onRecompute = vi.fn().mockResolvedValue(makePlan({ id: 'NEW', summary: 'again' }))
    const { unmount } = render(<PlanPreview plan={makePlan()} applyFn={vi.fn().mockRejectedValue(lost)} onRecompute={onRecompute} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-recompute')).toBeInTheDocument())
    unmount()
    render(<PlanPreview plan={makePlan({ expires_at: new Date(Date.now() - 1000).toISOString() })} onRecompute={onRecompute} />)
    fireEvent.click(screen.getByTestId('plan-recompute'))
    await waitFor(() => expect(screen.getByTestId('plan-summary')).toHaveTextContent('again'))
  })

  it('shows no recompute action without a callback, and reports a failed recompute', async () => {
    const { unmount } = render(<PlanPreview plan={makePlan({ expires_at: new Date(Date.now() - 1000).toISOString() })} />)
    expect(screen.queryByTestId('plan-recompute')).not.toBeInTheDocument()
    unmount()
    const onRecompute = vi.fn().mockRejectedValue(Object.assign(new Error('zone gone'), { code: 'not_found', status: 404 }))
    render(<PlanPreview plan={makePlan({ expires_at: new Date(Date.now() - 1000).toISOString() })} onRecompute={onRecompute} />)
    fireEvent.click(screen.getByTestId('plan-recompute'))
    await waitFor(() => expect(screen.getByTestId('plan-apply-error')).toHaveTextContent('zone gone'))
  })

  it('follows a job for install scopes until done', async () => {
    const job = { id: 'j1', plan_id: 'p', state: 'running', progress: 50, steps: [{ name: 'install bind packages', state: 'running' }], created_at: '', finished_at: null, error: null }
    const jobFn = vi.fn().mockResolvedValue({ ...job, state: 'done', progress: 100, steps: [{ name: 'install bind packages', state: 'done' }] })
    const onApplied = vi.fn()
    render(<PlanPreview plan={makePlan({ scope: 'install', engine: null })} applyFn={vi.fn().mockResolvedValue(job)} jobFn={jobFn} onApplied={onApplied} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-job')).toHaveTextContent('install bind packages'))
    await waitFor(() => expect(onApplied).toHaveBeenCalled(), { timeout: 4000 })
    expect(jobFn).toHaveBeenCalledWith('j1')
  })
})
