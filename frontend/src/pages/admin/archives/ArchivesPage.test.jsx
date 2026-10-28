// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../../services/api'

vi.mock('../../../services/api', () => {
  const api = {
    archives: {
      overview: vi.fn(), updateSettings: vi.fn(), createDestination: vi.fn(), updateDestination: vi.fn(), deleteDestination: vi.fn(),
      testDestination: vi.fn(), run: vi.fn(), list: vi.fn(), download: vi.fn(), upload: vi.fn(), identity: vi.fn(), inspect: vi.fn(), restorePlan: vi.fn(),
    },
    jobs: { get: vi.fn() },
    plans: { apply: vi.fn(), rollback: vi.fn(), get: vi.fn() },
    nodes: { list: vi.fn(async () => ({ items: [] })) },
  }
  return { api, default: api }
})
vi.mock('../../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => p !== 'admin:users' }) }))

const { default: ArchivesPage } = await import('./ArchivesPage')

const SETTINGS = { schedule_enabled: false, start_time: '03:15', interval_hours: 24, stagger_minutes: 15, keep_daily_count: 7, keep_weekly_count: 4, keep_monthly_count: 6, local_keep_count: 3, include_leases_enabled: true, verify_enabled: true, test_restore_days: 7, max_archive_mb: 512 }
const NODE = { node_id: 'n1', name: 'ns1', reachable: true, last_success: '2026-10-28T03:15:00Z', last_archive: { size: 1843200 }, next_run: null, running: false, complete: true, failures: {}, errors: {}, unreadable: [], test_restore: null }
const SFTP = { id: 'd1', type: 'sftp', name: 'Off site', enabled: true, params: { host: 'backup.example.lan', port: 22, username: 'pelagos', path: 'archives', host_key_fingerprint: `SHA256:${'A'.repeat(43)}` }, keep: null, secrets: { ssh_key: true }, error: null, status: [{ node_id: 'n1', failures: 2, error: 'connection refused' }] }
const ARCHIVE = { id: 'a1', node_id: 'n1', node_name: 'ns1', created_at: '2026-10-28T03:15:00Z', size: 1843200, sha256: 'ab', destinations: ['local', 'd1'], complete: true, verified_at: '2026-10-28T03:16:00Z', filename: 'ns1-20261028T031500Z.tar.gz.age', held_by: ['n1'] }
const overview = (over = {}) => ({ settings: SETTINGS, recipients: [], identity: { stored: false, retired: [] }, destinations: [SFTP], nodes: [NODE, { ...NODE, node_id: 'n2', name: 'ns2' }], ...over })

const renderPage = () => render(<MemoryRouter><ArchivesPage /></MemoryRouter>)

describe('ArchivesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.archives.overview.mockResolvedValue(overview())
    api.archives.list.mockResolvedValue({ items: [ARCHIVE], total: 1, page: 1, per_page: 25, meta: { unreachable: [] } })
  })

  it('refuses to schedule or run without a key, and shows the identity once after generating it', async () => {
    api.archives.identity.mockResolvedValue({ identity: `AGE-SECRET-KEY-1${'Q'.repeat(58)}`, recipients: [] })
    renderPage()
    expect(await screen.findByTestId('archives-no-key')).toBeInTheDocument()
    expect(screen.getByTestId('archives-run')).toBeDisabled()
    expect(within(screen.getByTestId('archives-schedule-toggle')).getByRole('switch')).toBeDisabled()
    fireEvent.click(screen.getByTestId('archives-key-generate'))
    const dialog = await screen.findByTestId('archives-password-dialog')
    fireEvent.change(within(dialog).getByTestId('archives-password'), { target: { value: 'secret' } })
    fireEvent.submit(dialog)
    await waitFor(() => expect(api.archives.identity).toHaveBeenCalledWith({ op: 'generate', password: 'secret' }))
    const once = await screen.findByTestId('archives-identity-once')
    expect(within(once).getByTestId('archives-identity-value')).toHaveTextContent('AGE-SECRET-KEY-1')
    expect(within(once).getByTestId('archives-identity-close')).toBeDisabled()
    fireEvent.click(within(once).getByTestId('archives-identity-saved'))
    expect(within(once).getByTestId('archives-identity-close')).toBeEnabled()
  })

  it('shows node state, destination failures, and tests a destination', async () => {
    api.archives.overview.mockResolvedValue(overview({ recipients: [{ recipient: `age1${'q'.repeat(58)}`, kind: 'cluster', label: 'cluster' }], identity: { stored: true, retired: [] } }))
    api.archives.testDestination.mockResolvedValue({ ok: false, node_id: 'n1', error: 'connection refused', targets: [{ label: 'Off site', ok: false, error: 'connection refused' }] })
    renderPage()
    const dest = await screen.findByTestId('archives-dest')
    expect(dest).toHaveTextContent('2 failures in a row, connection refused')
    expect(dest).toHaveTextContent('pelagos@backup.example.lan:22/archives')
    fireEvent.click(within(dest).getByTestId('archives-dest-card-test'))
    const result = await screen.findByTestId('archives-dest-card-result')
    expect(api.archives.testDestination).toHaveBeenCalledWith({ destination_id: 'd1' })
    expect(result.dataset.ok).toBe('false')
    expect(screen.getAllByTestId('archives-node')).toHaveLength(2)
    expect(screen.getByTestId('archives-run')).toBeEnabled()
  })

  it('edits a destination without echoing the stored key', async () => {
    api.archives.updateDestination.mockResolvedValue(SFTP)
    renderPage()
    fireEvent.click(await screen.findByTestId('archives-dest-edit'))
    const dialog = await screen.findByTestId('archives-dest-dialog')
    expect(within(dialog).getByTestId('archives-dest-key')).toHaveValue('')
    fireEvent.submit(dialog)
    await waitFor(() => expect(api.archives.updateDestination).toHaveBeenCalled())
    const [id, body] = api.archives.updateDestination.mock.calls[0]
    expect(id).toBe('d1')
    expect(body).not.toHaveProperty('secrets')
    expect(body).not.toHaveProperty('type')
  })

  it('restores: inspect, choose parts, then the restore plan', async () => {
    api.archives.inspect.mockResolvedValue({
      manifest: { node_name: 'ns1', created_at: ARCHIVE.created_at, complete: true },
      archive: ARCHIVE,
      target_node_id: 'n1',
      parts: [
        { id: 'bind.zone:_default/example.lan', engine: 'bind', node_id: 'n1', permission: 'write:dns.records', diff_summary: { add: 2, replace: 0, delete: 1 }, mode: 'diff', modes: ['diff', 'replace'] },
        { id: 'kea4.config', engine: 'kea4', node_id: 'n1', permission: 'write:dhcp.config', diff_summary: { changed: false } },
        { id: 'pelagos.settings:users', engine: 'pelagos', node_id: 'n1', permission: 'admin:users', diff_summary: { changed: true } },
      ],
      warnings: [],
    })
    api.archives.restorePlan.mockResolvedValue({ id: 'p1', scope: 'restore', state: 'validated', summary: 'restore', changes: [], validations: [], preconditions: [], target_node_ids: ['n1'], requires_confirmation: true, diff: '' })
    renderPage()
    fireEvent.click(await screen.findByTestId('archives-restore-open'))
    fireEvent.click(await screen.findByTestId('archives-restore-inspect'))
    await waitFor(() => expect(api.archives.inspect).toHaveBeenCalledWith('a1', { target_node_id: 'n1' }))
    const parts = await screen.findAllByTestId('archives-restore-part')
    expect(parts).toHaveLength(3)
    expect(within(parts[0]).getByRole('checkbox')).toBeChecked()
    expect(within(parts[1]).getByRole('checkbox')).not.toBeChecked()
    expect(within(parts[2]).getByRole('checkbox')).toBeDisabled()
    expect(parts[0]).toHaveTextContent('2 added, 0 replaced, 1 deleted')
    fireEvent.click(screen.getByTestId('archives-restore-build'))
    await waitFor(() => expect(api.archives.restorePlan).toHaveBeenCalledWith('a1', { target_node_id: 'n1', parts: [{ id: 'bind.zone:_default/example.lan', mode: 'diff' }] }))
    expect((await screen.findByTestId('archives-restore')).dataset.step).toBe('plan')
  })
})
