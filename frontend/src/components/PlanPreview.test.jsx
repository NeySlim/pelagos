// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import i18n from '../i18n'
import { PlanPreview, PlanPreviewModal } from './PlanPreview'

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
  it('shows the impact before the diff and the confirmation reasons', () => {
    const impact = [
      {
        kind: 'leases',
        severity: 'warning',
        text: '2 active leases in 192.0.2.0/24: their clients lose their address',
        message: { key: 'plan.impact.subnet_leases', params: { count: 2, subnet: '192.0.2.0/24' } },
        count: 3,
        examples: ['192.0.2.10 pc1 aa:bb:cc:dd:ee:01', '192.0.2.11 pc2 aa:bb:cc:dd:ee:02'],
      },
    ]
    render(<PlanPreview plan={makePlan({ impact, requires_confirmation: true, requires_confirmation_reasons: ['delete', 'leases_lost'] })} />)
    const section = screen.getByTestId('plan-impact')
    expect(section).toHaveTextContent('192.0.2.10 pc1')
    expect(section).toHaveTextContent('and 1 more')
    expect(section.compareDocumentPosition(screen.getByTestId('plan-diff')) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(screen.getByTestId('plan-confirm-reasons')).toHaveTextContent('a configuration object is deleted, active leases are lost')
    expect(screen.getByTestId('plan-apply')).toBeDisabled()
  })

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

  it('names the tool of an engine validation error', async () => {
    const err = Object.assign(new Error('The engine rejected the configuration'), {
      code: 'engine_validation_failed',
      errors: [{ tool: 'named-checkzone', message: 'zone example.lan/IN: has no NS records' }],
    })
    render(<PlanPreview plan={makePlan()} applyFn={vi.fn().mockRejectedValue(err)} />)
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-apply-error')).toHaveTextContent('named-checkzone: zone example.lan/IN'))
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

  describe('action bar', () => {
    afterEach(() => i18n.changeLanguage('en'))

    const longDiff = `--- a/example.lan.\n+++ b/example.lan.\n@@ -1,0 +1,58 @@\n${Array.from({ length: 57 }, (_, i) => `+h${i}.example.lan. 300 IN A 192.0.2.${i + 1}`).join('\n')}\n`

    it('folds a diff longer than 10 lines and counts its lines', () => {
      render(<PlanPreview plan={makePlan({ diff: longDiff })} />)
      const diff = screen.getByTestId('plan-diff')
      expect(diff).toHaveAttribute('data-open', 'false')
      expect(diff).toHaveTextContent('60 lines')
      fireEvent.click(diff.querySelector('button'))
      expect(diff).toHaveAttribute('data-open', 'true')
    })

    it('keeps a short diff open without a counter', () => {
      render(<PlanPreview plan={makePlan()} />)
      expect(screen.getByTestId('plan-diff')).toHaveAttribute('data-open', 'true')
      expect(screen.getByTestId('plan-diff')).not.toHaveTextContent(/\d+ lines?$/)
    })

    it('renders the pinned bar outside the scrolling body in the modal', () => {
      render(<PlanPreviewModal open plan={makePlan({ diff: longDiff, requires_confirmation: true, requires_confirmation_reasons: ['delete'] })} onClose={() => {}} />)
      const footer = screen.getByTestId('plan-footer')
      const preview = screen.getByTestId('plan-preview')
      expect(preview).toContainElement(footer)
      expect(footer.parentElement).toBe(preview)
      const scroller = preview.firstElementChild
      expect(scroller).toHaveClass('overflow-y-auto')
      expect(scroller).not.toContainElement(footer)
      expect(footer).toContainElement(screen.getByTestId('plan-confirm-checkbox'))
      expect(footer).toContainElement(screen.getByTestId('plan-confirm-reasons'))
      expect(footer).toContainElement(screen.getByTestId('plan-apply'))
      expect(screen.getByTestId('plan-close')).toHaveTextContent('Close')
    })

    it('pins the bar with sticky positioning outside a modal', () => {
      render(<PlanPreview plan={makePlan()} onClose={() => {}} />)
      expect(screen.getByTestId('plan-footer')).toHaveClass('sticky', 'bottom-0')
    })

    it('says Fermer and Revenir en arrière in French', async () => {
      await i18n.changeLanguage('fr')
      render(<PlanPreview plan={makePlan()} onClose={() => {}} applyFn={vi.fn().mockResolvedValue(applied())} getFn={vi.fn().mockResolvedValue(makePlan({ state: 'applied' }))} />)
      expect(screen.getByTestId('plan-close')).toHaveTextContent('Fermer')
      fireEvent.click(screen.getByTestId('plan-apply'))
      await waitFor(() => expect(screen.getByTestId('plan-rollback')).toHaveTextContent('Revenir en arrière'))
      expect(screen.getByTestId('plan-close')).toHaveTextContent('Fermer')
    })

    it('skips the checkbox when the caller already confirmed', async () => {
      const applyFn = vi.fn().mockResolvedValue(applied())
      render(<PlanPreview plan={makePlan({ requires_confirmation: true, requires_confirmation_reasons: ['delete'] })} preConfirmed applyFn={applyFn} getFn={vi.fn().mockResolvedValue(null)} />)
      expect(screen.queryByTestId('plan-confirm-checkbox')).not.toBeInTheDocument()
      expect(screen.getByTestId('plan-confirm-reasons')).toHaveTextContent('a configuration object is deleted')
      fireEvent.click(screen.getByTestId('plan-apply'))
      await waitFor(() => expect(applyFn).toHaveBeenCalledWith('01JBPLAN0000000000000000AA', true))
    })

    it('renders the partial option only when given', () => {
      const { unmount } = render(<PlanPreview plan={makePlan()} />)
      expect(screen.queryByTestId('plan-partial-checkbox')).not.toBeInTheDocument()
      unmount()
      const onChange = vi.fn()
      render(<PlanPreview plan={makePlan()} partialOption={{ checked: false, onChange, nodeIds: ['n2'] }} nodeName={(id) => ({ n1: 'ns1', n2: 'ns2' })[id] || id} />)
      expect(screen.getByTestId('plan-footer')).toHaveTextContent('Apply only on the reachable nodes (ns2 offline)')
      fireEvent.click(screen.getByTestId('plan-partial-checkbox'))
      expect(onChange).toHaveBeenCalledWith(true)
    })
  })

  it('names the apply nodes and a validation run on another node', async () => {
    const validations = [
      { ok: true, tool: 'named-checkzone', output: '', node_id: 'n1' },
      { ok: true, tool: 'remote_rrset', output: '', node_id: 'n2' },
    ]
    const applyFn = vi.fn().mockResolvedValue(applied())
    render(<PlanPreview plan={makePlan({ validations })} applyFn={applyFn} getFn={vi.fn().mockResolvedValue(null)} nodeName={(id) => ({ n1: 'ns1', n2: 'ns2' })[id] || id} />)
    expect(screen.getByTestId('plan-applied-on')).toHaveTextContent('Applies to ns1, ns2')
    const items = screen.getByTestId('plan-checklist').querySelectorAll('li')
    expect(items[0]).not.toHaveTextContent('validated on')
    expect(items[1]).toHaveTextContent('validated on ns2')
    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-applied-on')).toHaveTextContent('Applied on ns1, ns2'))
  })
  it('hides Apply with allowApply=false and Roll back with allowRollback=false', () => {
    const { unmount } = render(<PlanPreview plan={makePlan()} allowApply={false} />)
    expect(screen.queryByTestId('plan-apply')).toBeNull()
    unmount()
    const held = makePlan({ state: 'applied' })
    const first = render(<PlanPreview plan={held} />)
    expect(screen.getByTestId('plan-rollback')).toBeInTheDocument()
    first.unmount()
    render(<PlanPreview plan={held} allowRollback={false} />)
    expect(screen.queryByTestId('plan-rollback')).toBeNull()
  })

  it('offers rollback on an interrupted failed plan while its window is open', () => {
    const until = new Date(Date.now() + 600000).toISOString()
    const { unmount } = render(<PlanPreview plan={makePlan({ state: 'failed', interrupted: true, rollback_until: until })} />)
    expect(screen.getByTestId('plan-rollback')).toBeInTheDocument()
    unmount()
    render(<PlanPreview plan={makePlan({ state: 'failed', interrupted: true, rollback_until: null })} />)
    expect(screen.queryByTestId('plan-rollback')).toBeNull()
  })

  it('shows no clickable Roll back for a plan loaded while it rolls back', () => {
    render(<PlanPreview plan={makePlan({ state: 'rolling_back' })} />)
    expect(screen.queryByTestId('plan-rollback')).toBeNull()
  })

  it('reports a refused rollback and restores the plan state', async () => {
    const err = Object.assign(new Error('late'), { status: 410, code: 'plan_expired' })
    const onRollbackError = vi.fn()
    render(<PlanPreview plan={makePlan({ state: 'applied' })} rollbackFn={vi.fn().mockRejectedValue(err)} onRollbackError={onRollbackError} />)
    fireEvent.click(screen.getByTestId('plan-rollback'))
    await waitFor(() => expect(onRollbackError).toHaveBeenCalledWith(err))
    expect(screen.getByTestId('plan-rollback')).toBeInTheDocument()
  })
})
