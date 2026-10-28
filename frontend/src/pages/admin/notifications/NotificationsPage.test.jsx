// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { api } from '../../../services/api'

vi.mock('../../../services/api', () => {
  const api = {
    notifications: {
      overview: vi.fn(), createChannel: vi.fn(), updateChannel: vi.fn(), deleteChannel: vi.fn(), test: vi.fn(),
      setOrder: vi.fn(), mute: vi.fn(), unmute: vi.fn(), history: vi.fn(),
    },
    alerts: { list: vi.fn() },
    nodes: { list: vi.fn(async () => ({ items: [{ peer: { id: 'n1', name: 'ns1' } }, { peer: { id: 'n2', name: 'ns2' } }] })) },
  }
  return { api, default: api }
})
vi.mock('../../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: () => true }) }))

const { default: NotificationsPage } = await import('./NotificationsPage')

const CHANNEL = {
  id: 'ch1', type: 'ntfy', name: 'Phone', enabled: true, language: 'en',
  params: { url: 'https://ntfy.example.lan', topic: 'pelagos' },
  filters: { severity_min: 'warning', kinds_include: [], kinds_exclude: ['ha_transition'], node_ids: [], engines: [] },
  schedule: { reminder_hours: 12, send_resolved: true, confirm_seconds: null, quiet: null },
  secrets: { token: true, password: false },
  warnings: [{ field: 'params.url', message: 'plain http carries the secret unencrypted' }],
  status: { state: 'failing', since: '2026-10-28T09:00:00Z', last_sent_at: null, last_error: 'HTTP 401: unauthorized' },
}
const OVERVIEW = {
  channels: [CHANNEL],
  settings: { dispatch_enabled: true },
  sender: { node_id: 'n1', since: '2026-10-27T10:00:00Z', order: ['n1', 'n2'] },
  mute: null,
  queue: { pending: 2, failing: 1 },
}

const renderPage = () => render(<MemoryRouter initialEntries={['/admin/notifications']}><NotificationsPage /></MemoryRouter>)

describe('NotificationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.notifications.overview.mockResolvedValue(OVERVIEW)
    api.notifications.history.mockResolvedValue({ items: [{ id: 'h1', ts: '2026-10-28T10:00:00Z', channel_id: 'ch1', node_id: 'n1', events: [{ event: 'opened', alert_id: 'A1', kind: 'daemon_down', severity: 'critical' }], result: 'ok', error: null }], total: 1 })
    api.alerts.list.mockResolvedValue({
      items: [{ id: 'AF1', kind: 'notification_failed', severity: 'warning', state: 'open', subject: 'notify:ch1', title: 'notification channel Phone has been failing', title_message: null }],
      total: 1,
    })
  })

  it('shows the sender, the failing channel, its alert and the history', async () => {
    renderPage()
    const card = await screen.findByTestId('notify-channel')
    expect(card.dataset.state).toBe('failing')
    expect(within(card).getByTestId('notify-channel-error')).toHaveTextContent('HTTP 401')
    expect(within(card).getByTestId('notify-channel-warning')).toHaveTextContent('params.url: plain http carries')
    expect(screen.getByTestId('notify-queue-failing')).toHaveTextContent('1')
    await waitFor(() => expect(screen.getByTestId('notify-sender')).toHaveTextContent('ns1'))
    expect(await screen.findByTestId('notify-failed-alert')).toHaveTextContent('notification channel Phone')
    expect(api.alerts.list).toHaveBeenCalledWith(expect.objectContaining({ kind: 'notification_failed', state: 'open' }))
    expect(await screen.findByText('1 event')).toBeInTheDocument()
    expect(screen.getAllByTestId('notify-order-node').map((n) => n.dataset.node)).toEqual(['n1', 'n2'])
  })

  it('sends a test from a card and shows the service answer', async () => {
    api.notifications.test.mockResolvedValue({ ok: false, node_id: 'n1', duration_ms: 30, status: 401, error: 'unauthorized' })
    renderPage()
    fireEvent.click(await screen.findByTestId('notify-channel-test'))
    const result = await screen.findByTestId('notify-channel-test-result')
    expect(api.notifications.test).toHaveBeenCalledWith({ channel_id: 'ch1' })
    expect(result.dataset.ok).toBe('false')
    expect(result).toHaveTextContent('unauthorized')
  })

  it('edits a channel without echoing its stored token, and reorders the senders', async () => {
    api.notifications.updateChannel.mockResolvedValue(CHANNEL)
    api.notifications.setOrder.mockResolvedValue({ order: ['n2', 'n1'] })
    renderPage()
    fireEvent.click(await screen.findByTestId('notify-channel-edit'))
    const dialog = await screen.findByTestId('notify-channel-dialog')
    expect(within(dialog).getByTestId('notify-secret-token')).toHaveValue('')
    fireEvent.click(within(dialog).getByTestId('notify-dialog-save'))
    await waitFor(() => expect(api.notifications.updateChannel).toHaveBeenCalled())
    const [id, body] = api.notifications.updateChannel.mock.calls[0]
    expect(id).toBe('ch1')
    expect(body).not.toHaveProperty('secrets')
    expect(body.params).toEqual({ url: 'https://ntfy.example.lan', topic: 'pelagos' })

    fireEvent.click(screen.getAllByTestId('notify-order-down')[0])
    fireEvent.click(screen.getByTestId('notify-order-save'))
    await waitFor(() => expect(api.notifications.setOrder).toHaveBeenCalledWith(['n2', 'n1']))
  })

  it('mutes with a mandatory reason', async () => {
    api.notifications.mute.mockResolvedValue({ mute: {} })
    renderPage()
    fireEvent.click(await screen.findByTestId('notify-mute'))
    const dialog = await screen.findByTestId('notify-mute-dialog')
    fireEvent.submit(dialog)
    expect(api.notifications.mute).not.toHaveBeenCalled()
    expect(await within(dialog).findByText('Required')).toBeInTheDocument()
    fireEvent.change(within(dialog).getByTestId('notify-mute-comment'), { target: { value: 'kernel upgrade' } })
    fireEvent.submit(dialog)
    await waitFor(() => expect(api.notifications.mute).toHaveBeenCalled())
    const [until, comment] = api.notifications.mute.mock.calls[0]
    expect(comment).toBe('kernel upgrade')
    expect(Date.parse(until) - Date.now()).toBeLessThanOrEqual(2 * 3600000)
  })
})
