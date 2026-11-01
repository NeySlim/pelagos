// SPDX-License-Identifier: Apache-2.0
// Plans page: rows with state, author and rollback countdown, filters sent to GET /plans, the
// permission-dependent author filter, the plan modal opened from ?id= and its rollback gate.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import '../../i18n'
import { resetNodeNamesCache } from '../../hooks/useNodeNames'

const db = vi.hoisted(() => ({ rows: [], calls: [], perms: null, plan: null, planError: null, preview: [], who: { username: 'alice' }, admin: false, ws: {}, gets: 0 }))

vi.mock('../../services/api', () => {
  const api = {
    plans: {
      list: async (params) => {
        db.calls.push(params)
        return { items: db.rows, total: db.rows.length, page: 1, per_page: 50, meta: { node_id: 'N1' } }
      },
      get: async () => {
        db.gets += 1
        if (db.planError) throw db.planError
        return db.plan
      },
    },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/useWebSocket', async (importOriginal) => ({
  ...(await importOriginal()),
  useWsTopic: (topic, handler) => {
    if (topic) db.ws[topic] = handler
  },
}))
vi.mock('../../contexts/AuthContext', async (importOriginal) => ({
  ...(await importOriginal()),
  useAuth: () => ({ user: db.who, isAdmin: db.admin }),
}))
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => !db.perms || db.perms.includes(p) }) }))
vi.mock('../../components/PlanPreview', () => ({
  PlanPreview: (props) => {
    db.preview.push(props)
    return (
      <div data-testid="plan-preview" data-apply={String(props.allowApply)} data-rollback={String(props.allowRollback)}>
        {props.plan.summary}
        <button type="button" data-testid="fake-410" onClick={() => props.onRollbackError?.({ status: 410, code: 'plan_expired' })}>410</button>
      </div>
    )
  },
}))

const { default: PlansPage } = await import('./PlansPage')

const soon = () => new Date(Date.now() + 3 * 3600 * 1000 + 60000).toISOString()
const row = (over) => ({
  id: 'P1', scope: 'dns.rrset', engine: 'bind', node_id: 'N1', summary: 'Add www A', summary_message: null, created_by: 'alice',
  created_at: '2026-11-01T10:00:00Z', state: 'applied', expires_at: soon(), finished_at: null, rollback_until: soon(),
  interrupted: false, error: null, error_message: null, target_node_ids: ['N1', 'N2'], requires_confirmation: false, ...over,
})

const renderPage = (entry = '/plans') =>
  render(
    <MemoryRouter initialEntries={[entry]}>
      <PlansPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  resetNodeNamesCache()
  db.rows = [
    row({}),
    row({ id: 'P2', state: 'rolled_back', rollback_until: null, summary: 'Remove old A' }),
    row({ id: 'P3', state: 'applied', rollback_until: '2020-01-01T00:00:00Z', summary: 'Old change' }),
    row({ id: 'P4', state: 'failed', rollback_until: null, summary: 'Broken', error: 'named-checkconf failed' }),
  ]
  db.calls = []
  db.perms = null
  db.plan = row({})
  db.planError = null
  db.preview = []
  db.who = { username: 'alice' }
  db.admin = false
  db.ws = {}
  db.gets = 0
})

describe('PlansPage', () => {
  it('lists the plans with their rollback window', async () => {
    renderPage()
    await screen.findByText('Add www A')
    const left = screen.getAllByTestId('plan-rollback-left')
    expect(left.map((n) => n.dataset.status)).toEqual(['open', 'none', 'closed', 'none'])
    expect(left[0]).toHaveTextContent(/3h \d+m left/)
    expect(screen.getByTestId('plan-row-error')).toHaveTextContent('named-checkconf failed')
    expect(await screen.findByText('Plans of')).toBeInTheDocument()
  })

  it('sends the filters of the URL and shows the author filter to read:audit only', async () => {
    renderPage('/plans?state=applied&user=alice')
    await screen.findByText('Add www A')
    expect(db.calls.at(-1)).toMatchObject({ state: 'applied', user: 'alice' })
    expect(screen.getByTestId('plans-filter-user')).toBeInTheDocument()
  })

  it('hides the author filter without read:audit', async () => {
    db.perms = []
    renderPage()
    await screen.findByText('Add www A')
    expect(screen.queryByTestId('plans-filter-user')).toBeNull()
  })

  it('opens the plan of ?id= read only, with Roll back while the window is open', async () => {
    renderPage('/plans?id=P1')
    const preview = await screen.findByTestId('plan-preview')
    expect(preview.dataset.apply).toBe('false')
    expect(preview.dataset.rollback).toBe('true')
    expect(screen.getByTestId('plan-detail-audit')).toHaveAttribute('href', '/audit?plan_id=P1')
  })

  it('offers no rollback once the window is closed or when the plan never had one', async () => {
    db.plan = row({ id: 'P3', rollback_until: '2020-01-01T00:00:00Z' })
    const { unmount } = renderPage('/plans?id=P3')
    expect((await screen.findByTestId('plan-preview')).dataset.rollback).toBe('false')
    expect(screen.getByTestId('plan-rollback-closed')).toBeInTheDocument()
    unmount()
    db.plan = row({ id: 'P5', rollback_until: null })
    renderPage('/plans?id=P5')
    expect((await screen.findByTestId('plan-preview')).dataset.rollback).toBe('false')
    expect(screen.getByTestId('plan-rollback-none')).toBeInTheDocument()
  })

  it('says so when the node no longer holds the plan, and still links the audit', async () => {
    db.planError = Object.assign(new Error('gone'), { status: 410, code: 'plan_expired' })
    renderPage('/plans?id=P9')
    const gone = await screen.findByTestId('plan-detail-gone')
    expect(within(gone).getByTestId('plan-detail-audit')).toHaveAttribute('href', '/audit?plan_id=P9')
  })

  it('opens a plan from its row', async () => {
    renderPage()
    await userEvent.click(await screen.findByText('Add www A'))
    await waitFor(() => expect(screen.getByTestId('plan-preview')).toBeInTheDocument())
  })

  it('offers Roll back to the creator or an admin only, not to another reader of the plan', async () => {
    db.who = { username: 'bob' }
    const first = renderPage('/plans?id=P1')
    expect((await screen.findByTestId('plan-preview')).dataset.rollback).toBe('false')
    expect(screen.getByTestId('plan-rollback-not-yours')).toHaveTextContent('alice')
    first.unmount()
    db.admin = true
    renderPage('/plans?id=P1')
    expect((await screen.findByTestId('plan-preview')).dataset.rollback).toBe('true')
  })

  it('treats an interrupted failed plan with a window as rollable', async () => {
    db.plan = row({ id: 'P6', state: 'failed', interrupted: true })
    renderPage('/plans?id=P6')
    expect((await screen.findByTestId('plan-preview')).dataset.rollback).toBe('true')
  })

  it('hides Roll back and refreshes the list after a 410 on the rollback', async () => {
    renderPage('/plans?id=P1')
    await userEvent.click(await screen.findByTestId('fake-410'))
    await waitFor(() => expect(screen.getByTestId('plan-preview').dataset.rollback).toBe('false'))
    expect(screen.getByTestId('plan-rollback-closed')).toBeInTheDocument()
    await waitFor(() => expect(db.calls.length).toBeGreaterThan(1))
  })

  it('reloads the open plan when the node says it changed, and shows it gone once it expired', async () => {
    renderPage('/plans?id=P1')
    await screen.findByTestId('plan-preview')
    db.plan = row({ state: 'rolled_back', rollback_until: null })
    db.ws.plans({ event: 'rolled_back', data: { plan_id: 'P1' } })
    await waitFor(() => expect(db.gets).toBe(2))
    db.planError = Object.assign(new Error('gone'), { status: 410 })
    db.ws.plans({ event: 'expired', data: { plan_id: 'P1' } })
    expect(await screen.findByTestId('plan-detail-gone')).toBeInTheDocument()
    // Events of other plans and per-node steps do not reload.
    const gets = db.gets
    db.ws.plans({ event: 'step', data: { plan_id: 'P1' } })
    db.ws.plans({ event: 'applied', data: { plan_id: 'P7' } })
    expect(db.gets).toBe(gets)
  })

  it('does not send the author filter without read:audit', async () => {
    db.perms = []
    renderPage('/plans?user=bob')
    await screen.findByText('Add www A')
    expect(db.calls.at(-1)).not.toHaveProperty('user')
  })

  it('offers no expired state in the state filter', async () => {
    renderPage()
    await screen.findByText('Add www A')
    expect(screen.queryByText('Expired')).toBeNull()
  })

  it('refreshes the list once for a burst of plan events', async () => {
    renderPage()
    await screen.findByText('Add www A')
    const before = db.calls.length
    for (let i = 0; i < 5; i += 1) db.ws.plans({ event: 'applied', data: { plan_id: 'P1' } })
    await waitFor(() => expect(db.calls.length).toBe(before + 1))
    await new Promise((r) => setTimeout(r, 700))
    expect(db.calls.length).toBe(before + 1)
  })
})
