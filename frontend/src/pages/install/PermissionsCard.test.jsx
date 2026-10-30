// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PermissionsCard from './PermissionsCard'
import { api } from '../../services/api'
import { failedChecks, fixableIds } from './permissions'

vi.mock('../../services/api', () => {
  const api = {
    install: { permissions: vi.fn(), security: vi.fn(), securityPlan: vi.fn() },
    plans: { apply: vi.fn(), get: vi.fn(), rollback: vi.fn() },
    jobs: { get: vi.fn() },
  }
  return { api, default: api }
})

// Shapes of core.permguard.Check.to_dict() as GET /install/permissions sends them.
const ZONE = '/etc/bind/cache/pelagos'
const COMMAND = `install -d -o bind -g bind -m 2775 ${ZONE}`
const ok = (path, purpose) => ({ path, kind: 'dir', engine: 'bind', purpose, ok: true, route: 'direct', owner: 'bind', group: 'bind', mode: '2775' })
const bad = {
  path: `${ZONE}/rpz`, kind: 'dir', engine: 'bind', purpose: 'rpz_dir', ok: false, problem: 'denied',
  owner: 'bind', group: 'bind', mode: '0755', probed: '/etc/bind/cache', command: COMMAND,
  finding_id: `bind:path_access:${ZONE}`,
  text: `RPZ folder ${ZONE}/rpz: cannot be created`,
  message: {
    key: 'permission.finding',
    params: {
      path: `${ZONE}/rpz`, what: { key: 'permission.purpose.rpz_dir', params: {} }, probed: '/etc/bind/cache',
      owner: 'bind', group: 'bind', mode: '0755', missing: { key: 'permission.problem.denied.dir', params: {} }, command: COMMAND,
    },
  },
}

describe('permission checks', () => {
  it('lists the failed checks and the findings the helper fixes, once each', () => {
    const second = { ...bad, path: ZONE, purpose: 'zone_dir' }
    const manual = { ...bad, path: '/srv/zones', finding_id: undefined, problem: 'read_only' }
    const checks = [ok('/etc/bind/pelagos', 'include_dir'), bad, second, manual]
    expect(failedChecks(checks)).toHaveLength(3)
    expect(fixableIds(checks)).toEqual([`bind:path_access:${ZONE}`])
    expect(fixableIds(undefined)).toEqual([])
  })
})

describe('PermissionsCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows every path, the finding and the command, and plans the fix', async () => {
    api.install.permissions.mockResolvedValue({ node_id: 'n2', available: true, checks: [ok(ZONE, 'zone_dir'), bad] })
    api.install.security.mockResolvedValue({ findings: [{ id: `bind:path_access:${ZONE}` }, { id: 'bind:other' }] })
    api.install.securityPlan.mockResolvedValue({ id: 'p1', scope: 'security', state: 'validated', changes: [], validations: [], target_node_ids: ['n2'], diff: '', summary: 'fix' })
    render(<MemoryRouter><PermissionsCard node="n2" /></MemoryRouter>)
    expect(await screen.findByTestId('permissions-state')).toHaveTextContent('1 path not writable')
    expect(api.install.permissions).toHaveBeenCalledWith('n2')
    const rows = screen.getAllByTestId('permissions-check')
    expect(rows).toHaveLength(2)
    expect(rows[1]).toHaveAttribute('data-ok', 'no')
    expect(rows[1]).toHaveTextContent('bind:bind 0755')
    expect(rows[1]).toHaveTextContent(`RPZ folder ${ZONE}/rpz: cannot be created: no write permission on the parent folder`)
    expect(screen.getByTestId('permissions-command')).toHaveTextContent(COMMAND)
    fireEvent.click(screen.getByTestId('permissions-fix'))
    await waitFor(() => expect(api.install.securityPlan).toHaveBeenCalledWith({ n2: [`bind:path_access:${ZONE}`] }))
  })

  it('sends only the ids the security audit lists', async () => {
    const stale = { ...bad, path: '/srv/x', finding_id: 'bind:path_access:/srv/x' }
    api.install.permissions.mockResolvedValue({ node_id: 'n2', available: true, checks: [bad, stale] })
    api.install.security.mockResolvedValue({ findings: [{ id: `bind:path_access:${ZONE}` }] })
    api.install.securityPlan.mockResolvedValue({ id: 'p1', scope: 'security', state: 'validated', changes: [], validations: [], target_node_ids: ['n2'], diff: '', summary: 'fix' })
    render(<MemoryRouter><PermissionsCard node="n2" /></MemoryRouter>)
    fireEvent.click(await screen.findByTestId('permissions-fix'))
    await waitFor(() => expect(api.install.securityPlan).toHaveBeenCalledWith({ n2: [`bind:path_access:${ZONE}`] }))
    expect(api.install.security).toHaveBeenCalledWith('n2')
  })

  it('says so when every path is writable, with no fix button', async () => {
    api.install.permissions.mockResolvedValue({ node_id: 'n1', available: true, checks: [ok(ZONE, 'zone_dir')] })
    render(<MemoryRouter><PermissionsCard /></MemoryRouter>)
    expect(await screen.findByTestId('permissions-state')).toHaveTextContent('all writable')
    expect(screen.queryByTestId('permissions-fix')).toBeNull()
  })

  it('an older node cannot answer', async () => {
    api.install.permissions.mockResolvedValue({ node_id: 'n3', available: false, checks: [], error: 'not available on this node' })
    render(<MemoryRouter><PermissionsCard node="n3" /></MemoryRouter>)
    expect(await screen.findByTestId('permissions-unavailable')).toHaveTextContent('not available on this node')
  })
})
