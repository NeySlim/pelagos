// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const apply = vi.fn()
const rollback = vi.fn()
const get = vi.fn()
vi.mock('../../services/api', () => {
  const api = { plans: { apply: (...a) => apply(...a), rollback: (...a) => rollback(...a), get: (...a) => get(...a) }, jobs: { get: vi.fn() } }
  return { api, default: api }
})

const { RecordEditor } = await import('./RecordEditor')

function makePlan(changes, overrides = {}) {
  return {
    id: '01JBPLANRECORD00000000000AA',
    created_at: '2026-10-24T10:00:00Z',
    created_by: 'alice',
    node_id: 'n1',
    scope: 'dns.rrset',
    engine: 'bind',
    summary: `${changes.length} change(s) in example.lan.`,
    changes,
    diff: '--- a/example.lan.\n+++ b/example.lan.\n@@ -0,0 +1 @@\n+www.example.lan. 3600 IN A 192.0.2.80\n',
    preconditions: [{ kind: 'rrset_absent', node_id: 'n1', subject: 'example.lan./www.example.lan./A', value: '' }],
    validations: [{ ok: true, tool: 'dnspython', output: '', node_id: 'n1' }],
    target_node_ids: ['n1'],
    requires_confirmation: false,
    state: 'validated',
    expires_at: new Date(Date.now() + 600000).toISOString(),
    error: null,
    ...overrides,
  }
}

const result = (state) => ({
  plan_id: '01JBPLANRECORD00000000000AA',
  state,
  results: [{ node_id: 'n1', ok: true, message: 'NOERROR', rolled_back: state === 'rolled_back', audit_ids: ['a1'] }],
  finished_at: '2026-10-24T10:00:02Z',
})

const fill = (testId, value) => fireEvent.change(screen.getByTestId(testId), { target: { value } })
const submit = () => fireEvent.click(screen.getByRole('button', { name: 'Preview the plan' }))

beforeEach(() => {
  apply.mockReset().mockResolvedValue(result('applied'))
  rollback.mockReset().mockResolvedValue(result('rolled_back'))
  get.mockReset().mockResolvedValue({ expires_at: new Date(Date.now() + 600000).toISOString() })
})

const covered = (ip, current = [], name = 'www.example.lan.') => ({
  ip,
  view: '_default',
  ptr_name: `${ip.split('.').reverse().join('.')}.in-addr.arpa.`,
  reverse_zone: '2.0.192.in-addr.arpa.',
  covered: true,
  reason: null,
  current,
  points_here: current.includes(name),
  conflict: current.length > 0 && !current.includes(name),
})

describe('RecordEditor PTR option', () => {
  const lookupFn = () => vi.fn().mockResolvedValue({ items: [] })
  const planFn = () => vi.fn().mockImplementation(async (_zone, changes) => makePlan(changes))

  it('on edit, the PTR of a removed address is removed even when the new one is not covered', async () => {
    const rrset = { name: 'www.example.lan.', rtype: 'A', ttl: 3600, rdata: ['192.0.2.10'] }
    const coverageFn = vi.fn().mockResolvedValue({
      items: [{ ip: '198.51.100.7', covered: false, reason: 'no_reverse_zone', current: [] }, covered('192.0.2.10', ['www.example.lan.'])],
    })
    const plan = planFn()
    render(<RecordEditor open zone="example.lan." mode="edit" rrset={rrset} planFn={plan} lookupFn={vi.fn()} coverageFn={coverageFn} onClose={vi.fn()} />)
    fill('record-rdata', '198.51.100.7')
    await waitFor(() => expect(screen.getByTestId('record-ptr-sync')).toBeChecked())
    expect(coverageFn).toHaveBeenLastCalledWith({ addresses: ['198.51.100.7', '192.0.2.10'], name: 'www.example.lan.' })
    fireEvent.click(screen.getByTestId('record-ptr-sync'))
    expect(screen.getByTestId('record-ptr-stays')).toHaveTextContent('192.0.2.10')
    fireEvent.click(screen.getByTestId('record-ptr-sync'))
    submit()
    await waitFor(() => expect(plan).toHaveBeenCalled())
    expect(plan.mock.calls[0][3]).toEqual({ sync: true, delete: true })
  })

  it('is checked when a reverse zone covers the address and goes in the same plan', async () => {
    const coverageFn = vi.fn().mockResolvedValue({ items: [covered('192.0.2.80')] })
    const plan = planFn()
    render(<RecordEditor open zone="example.lan." view="inside" mode="add" planFn={plan} lookupFn={lookupFn()} coverageFn={coverageFn} onClose={vi.fn()} />)
    fill('record-owner', 'www')
    fill('record-rdata', '192.0.2.80')
    await waitFor(() => expect(screen.getByTestId('record-ptr-sync')).toBeChecked())
    expect(coverageFn).toHaveBeenLastCalledWith({ addresses: ['192.0.2.80'], name: 'www.example.lan.', view: 'inside' })
    expect(screen.getByTestId('record-ptr-help')).toHaveTextContent('2.0.192.in-addr.arpa.')
    submit()
    await waitFor(() => expect(plan).toHaveBeenCalled())
    expect(plan.mock.calls[0][3]).toEqual({ sync: true, delete: true })
  })

  it('is disabled with the reason when no reverse zone covers the address', async () => {
    const coverageFn = vi.fn().mockResolvedValue({ items: [{ ip: '198.51.100.7', covered: false, reason: 'no_reverse_zone', current: [] }] })
    const plan = planFn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={plan} lookupFn={lookupFn()} coverageFn={coverageFn} onClose={vi.fn()} />)
    fill('record-owner', 'ext')
    fill('record-rdata', '198.51.100.7')
    await waitFor(() => expect(screen.getByTestId('record-ptr-help')).toHaveTextContent('No reverse zone served by the cluster covers this address'))
    expect(screen.getByTestId('record-ptr-sync')).toBeDisabled()
    submit()
    await waitFor(() => expect(plan).toHaveBeenCalled())
    expect(plan.mock.calls[0][3]).toBeUndefined()
  })

  it('shows a PTR that points elsewhere, and can be turned off', async () => {
    const coverageFn = vi.fn().mockResolvedValue({ items: [covered('192.0.2.100', ['pc1.example.lan.'])] })
    const plan = planFn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={plan} lookupFn={lookupFn()} coverageFn={coverageFn} onClose={vi.fn()} />)
    fill('record-owner', 'www')
    fill('record-rdata', '192.0.2.100')
    expect(await screen.findByTestId('record-ptr-conflict')).toHaveTextContent('192.0.2.100 points to pc1.example.lan.')
    fireEvent.click(screen.getByTestId('record-ptr-sync'))
    expect(screen.queryByTestId('record-ptr-conflict')).toBeNull()
    submit()
    await waitFor(() => expect(plan).toHaveBeenCalled())
    expect(plan.mock.calls[0][3]).toBeUndefined()
  })

  it('offers to delete the PTR of a deleted A', async () => {
    const rrset = { name: 'www.example.lan.', rtype: 'A', ttl: 300, rdata: ['192.0.2.10', '192.0.2.11'] }
    const coverageFn = vi.fn().mockResolvedValue({ items: [covered('192.0.2.10', ['www.example.lan.']), covered('192.0.2.11')] })
    const plan = planFn()
    render(<RecordEditor open zone="example.lan." mode="delete" rrset={rrset} planFn={plan} lookupFn={vi.fn()} coverageFn={coverageFn} onClose={vi.fn()} />)
    await waitFor(() => expect(screen.getByTestId('record-ptr-sync')).toBeChecked())
    expect(screen.getByTestId('record-ptr')).toHaveTextContent('Also delete the PTR that points to this name')
    submit()
    await waitFor(() => expect(plan).toHaveBeenCalled())
    expect(plan.mock.calls[0][3]).toEqual({ sync: false, delete: true })
  })

  it('has no PTR option for other types', async () => {
    const coverageFn = vi.fn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={planFn()} lookupFn={lookupFn()} coverageFn={coverageFn} onClose={vi.fn()} defaults={{ rtype: 'TXT' }} />)
    fill('record-owner', 'www')
    fill('record-rdata', 'hello')
    await new Promise((r) => setTimeout(r, 400))
    expect(screen.queryByTestId('record-ptr')).toBeNull()
    expect(coverageFn).not.toHaveBeenCalled()
  })
})

describe('RecordEditor', () => {
  it('previews, builds the plan, applies and rolls back', async () => {
    const lookupFn = vi.fn().mockResolvedValue({ items: [] })
    const planFn = vi.fn().mockImplementation(async (_zone, changes) => makePlan(changes))
    const onApplied = vi.fn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={planFn} lookupFn={lookupFn} onApplied={onApplied} onClose={vi.fn()} />)

    fill('record-owner', 'www')
    fill('record-rdata', '192.0.2.80')
    expect(screen.getByTestId('record-preview')).toHaveTextContent('+www.example.lan. 3600 IN A 192.0.2.80')

    submit()
    await waitFor(() => expect(screen.getByTestId('record-editor-plan')).toBeInTheDocument())
    expect(lookupFn).toHaveBeenCalledWith('example.lan.', { name: 'www.example.lan.', type: 'A' })
    expect(planFn).toHaveBeenCalledWith(
      'example.lan.',
      [{ op: 'add', target: 'example.lan./www/A', before: null, after: { name: 'www.example.lan.', rtype: 'A', ttl: 3600, rdata: ['192.0.2.80'] }, node_ids: [] }],
      undefined,
      undefined,
    )
    expect(screen.getByTestId('plan-summary')).toHaveTextContent('1 change(s) in example.lan.')
    expect(screen.getByTestId('plan-diff')).toHaveTextContent('www.example.lan. 3600 IN A 192.0.2.80')

    fireEvent.click(screen.getByTestId('plan-apply'))
    await waitFor(() => expect(screen.getByTestId('plan-result')).toHaveTextContent('NOERROR'))
    expect(apply).toHaveBeenCalledWith('01JBPLANRECORD00000000000AA', false)
    expect(onApplied).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByTestId('plan-rollback'))
    await waitFor(() => expect(rollback).toHaveBeenCalledWith('01JBPLANRECORD00000000000AA'))
    await waitFor(() => expect(onApplied).toHaveBeenCalledTimes(2))
  })

  it('shows field errors and builds nothing while the form is invalid', async () => {
    const planFn = vi.fn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={planFn} lookupFn={vi.fn()} onClose={vi.fn()} />)
    fill('record-owner', 'bad..name')
    fill('record-rdata', '2001:db8::1')
    expect(screen.getByTestId('record-preview-pending')).toBeInTheDocument()
    submit()
    expect(await screen.findByText('Each value must be an IPv4 address')).toBeInTheDocument()
    expect(screen.getByText('Invalid name, or outside the zone')).toBeInTheDocument()
    expect(planFn).not.toHaveBeenCalled()
  })

  it('merges an add into the existing RRset as a replace', async () => {
    const existing = { name: 'www.example.lan.', rtype: 'A', ttl: 300, rdata: ['192.0.2.10'] }
    const planFn = vi.fn().mockImplementation(async (_zone, changes) => makePlan(changes))
    render(<RecordEditor open zone="example.lan." view="internal" mode="add" planFn={planFn} lookupFn={vi.fn().mockResolvedValue({ items: [existing] })} onClose={vi.fn()} />)
    fill('record-owner', 'www')
    fill('record-ttl', '300')
    fill('record-rdata', '192.0.2.11')
    submit()
    await waitFor(() => expect(planFn).toHaveBeenCalled())
    const [, changes, view] = planFn.mock.calls[0]
    expect(view).toBe('internal')
    expect(changes).toEqual([{ op: 'replace', target: 'example.lan./www/A', before: existing, after: { name: 'www.example.lan.', rtype: 'A', ttl: 300, rdata: ['192.0.2.10', '192.0.2.11'] }, node_ids: [] }])
  })

  it('edits an RRset: nothing to send until a value changes', async () => {
    const rrset = { name: 'example.lan.', rtype: 'MX', ttl: 3600, rdata: ['10 mail.example.lan.'] }
    const planFn = vi.fn().mockImplementation(async (_zone, changes) => makePlan(changes))
    render(<RecordEditor open zone="example.lan." mode="edit" rrset={rrset} planFn={planFn} lookupFn={vi.fn()} onClose={vi.fn()} />)
    expect(screen.getByTestId('record-owner')).toHaveValue('@')
    expect(screen.getByTestId('record-preview-unchanged')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Preview the plan' })).toBeDisabled()
    fill('record-rdata', '10 mail.example.lan.\n20 backup.example.lan.')
    expect(screen.getByTestId('record-preview')).toHaveTextContent('+example.lan. 3600 IN MX 20 backup.example.lan.')
    submit()
    await waitFor(() => expect(planFn).toHaveBeenCalled())
    expect(planFn.mock.calls[0][1]).toEqual([
      { op: 'replace', target: 'example.lan./@/MX', before: rrset, after: { name: 'example.lan.', rtype: 'MX', ttl: 3600, rdata: ['10 mail.example.lan.', '20 backup.example.lan.'] }, node_ids: [] },
    ])
  })

  it('deletes an RRset', async () => {
    const rrset = { name: 'old.example.lan.', rtype: 'TXT', ttl: 60, rdata: ['"bye"'] }
    const planFn = vi.fn().mockImplementation(async (_zone, changes) => makePlan(changes))
    render(<RecordEditor open zone="example.lan." mode="delete" rrset={rrset} planFn={planFn} lookupFn={vi.fn()} onClose={vi.fn()} />)
    expect(screen.getByTestId('record-preview')).toHaveTextContent('-old.example.lan. 60 IN TXT "bye"')
    submit()
    await waitFor(() => expect(planFn).toHaveBeenCalled())
    expect(planFn.mock.calls[0][1]).toEqual([{ op: 'delete', target: 'example.lan./old/TXT', before: rrset, after: null, node_ids: [] }])
  })

  it('shows the server error when the plan is refused', async () => {
    const err = Object.assign(new Error('Some fields are invalid'), { code: 'validation_error', errors: [{ field: 'changes[0].after.ttl', message: 'must be >= 0' }] })
    render(<RecordEditor open zone="example.lan." mode="add" planFn={vi.fn().mockRejectedValue(err)} lookupFn={vi.fn().mockResolvedValue({ items: [] })} onClose={vi.fn()} />)
    fill('record-owner', 'www')
    fill('record-rdata', '192.0.2.80')
    submit()
    expect(await screen.findByTestId('record-editor-error')).toHaveTextContent('must be >= 0')
    expect(screen.queryByTestId('record-editor-plan')).not.toBeInTheDocument()
  })
})

describe('RecordEditor TTL', () => {
  it('a negative TTL says why instead of being blocked silently by the browser', async () => {
    const plan = vi.fn()
    render(<RecordEditor open zone="example.lan." mode="add" planFn={plan} lookupFn={vi.fn()} coverageFn={vi.fn().mockResolvedValue({ items: [] })} onClose={vi.fn()} />)
    fill('record-owner', 'app')
    fill('record-ttl', '-5')
    fill('record-rdata', '192.0.2.60')
    expect(screen.getByTestId('record-ttl')).not.toHaveAttribute('min')
    submit()
    expect(await screen.findByText('TTL must be a whole number of seconds')).toBeInTheDocument()
    expect(plan).not.toHaveBeenCalled()
  })
})
