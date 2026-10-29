// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { StrictMode } from 'react'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { subjectLink, jobResult, exceptionItems, alertOrigin, unavailableNodes } from './lib'

const N1 = '01JB0000000000000000NS1AAA'
const N2 = '01JB0000000000000000NS2BBB'
const ALERTS = [
  { id: 'A1', kind: 'ptr_mismatch', severity: 'warning', state: 'open', node_id: null, engine: null, subject: 'ip:192.0.2.106', title: 'PTR of 192.0.2.106 names another host', details: { ip: '192.0.2.106', exception_keys: ['192.0.2.106|pc7.example.lan.'] }, reported_by: [N1, N2], first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' },
  { id: 'A2', kind: 'pool_full', severity: 'critical', state: 'open', node_id: N1, engine: 'kea4', subject: 'kea4:subnet:3:pool:192.0.2.200-192.0.2.219', title: 'Pool is full', details: {}, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' },
  { id: 'A3', kind: 'security_advisory', severity: 'warning', state: 'open', node_id: N1, engine: 'kea4', subject: 'kea4:advisories', title: 'upstream kea4 2.6.3 is affected', details: { distribution_data: { name: null, reason: 'no_tracker', unavailable: { since: '2026-10-27T10:00:00Z', reason: 'download deadline exceeded' } } }, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' },
]

// Resolved, so absent from the default (open) list: reached by /alerts?alert=<id> only.
const RESOLVED = { id: 'A9', kind: 'daemon_down', severity: 'critical', state: 'resolved', node_id: N2, engine: 'bind', subject: 'daemon:bind', title: 'named is down', details: {}, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T10:05:00Z', resolved_at: '2026-10-24T10:05:00Z' }
let mute = null

const calls = { list: vi.fn(), ack: vi.fn(), run: vi.fn(), addException: vi.fn() }
const notify = { showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showPrompt: vi.fn() }
let canWrite = true
let canDns = true
let listMeta = {}
let extra = []
let resolverFallback = null
const PROPOSING = { id: 'A5', kind: 'resolver_health', severity: 'critical', state: 'open', node_id: N1, engine: 'bind', subject: 'resolver:latency', title: 'resolver p95 is slow', details: { p95: 2000, remediation: 'resolver_fallback' }, first_seen: '2026-10-24T10:00:00Z', last_seen: '2026-10-24T11:00:00Z' }

vi.mock('../../services/api', () => {
  const api = {
    alerts: {
      summary: async () => ({ open: 2, acked: 1, by_severity: { critical: 1, warning: 1, info: 0 }, by_kind: {} }),
      list: async (q) => {
        calls.list(q)
        if (!q.state && q.per_page === 500) return { items: [...ALERTS, RESOLVED], page: 1, per_page: 500, total: 4, meta: listMeta }
        return { items: [...ALERTS, ...extra], page: 1, per_page: 50, total: 2 + extra.length, meta: listMeta }
      },
      ack: async (id, comment) => {
        calls.ack(id, comment)
        return { ...ALERTS[0], state: 'acked' }
      },
      addException: async (body) => {
        calls.addException(body)
        return { id: 'E1', ...body }
      },
      runConsistency: async () => {
        calls.run()
        return { job_id: 'J1' }
      },
    },
    resolverHealth: { health: async () => ({ nodes: [], fallback: resolverFallback }) },
    jobs: { get: async () => ({ id: 'J1', state: 'done', steps: [{ name: 'consistency', state: 'done' }, { name: 'result', output: { found: 3 } }] }) },
    notifications: {
      overview: async () => ({ channels: [{ id: 'ch1', name: 'Phone' }, { id: 'ch2', name: 'On-call mail' }], mute }),
      history: async () => ({
        items: [
          { id: 'h1', ts: '2026-10-24T10:01:00Z', channel_id: 'ch1', result: 'ok', events: [{ event: 'opened', alert_id: 'A9' }] },
          { id: 'h2', ts: '2026-10-24T10:02:00Z', channel_id: 'ch2', result: 'ok', events: [{ event: 'opened', alert_id: 'A9' }] },
          { id: 'h3', ts: '2026-10-24T10:03:00Z', channel_id: 'ch2', result: 'ok', events: [{ event: 'opened', alert_id: 'A2' }] },
        ],
        total: 3,
      }),
    },
    nodes: { list: async () => ({ items: [{ peer: { id: N1, name: 'ns1' }, is_self: true }, { peer: { id: N2, name: 'ns2' }, is_self: false }] }) },
  }
  return { api, default: api }
})
vi.mock('../../hooks/usePermission', () => ({ usePermission: () => ({ hasPermission: (p) => (p === 'write:alerts' ? canWrite : p === 'write:dns.config' ? canDns : true) }) }))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => notify }))

const { default: AlertsPage } = await import('./AlertsPage')

const renderPage = (url = '/alerts') =>
  render(
    <MemoryRouter initialEntries={[url]}>
      <AlertsPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  canWrite = true
  canDns = true
  extra = []
  resolverFallback = null
  listMeta = {}
  mute = null
  for (const fn of [...Object.values(calls), ...Object.values(notify)]) fn.mockReset()
})

describe('AlertsPage', () => {
  it('names the node of each alert, or the nodes reporting a cluster-wide one', async () => {
    renderPage()
    const table = await screen.findByTestId('alerts-table')
    await waitFor(() => expect(within(table).getAllByTestId('alert-origin').length).toBe(3))
    const origins = within(table).getAllByTestId('alert-origin').map((e) => e.textContent)
    expect(origins).toContain('Clustervia ns1, ns2')
    expect(origins).toContain('ns1')
    expect(screen.queryByTestId('alerts-unavailable')).toBeNull()
  })

  it('says which nodes are missing from a partial view', async () => {
    listMeta = { unavailable: [{ node_id: N2, name: 'ns2', error: 'node ns2 is offline: unreachable' }] }
    renderPage()
    const notice = await screen.findByTestId('alerts-unavailable')
    expect(notice).toHaveTextContent('Alerts of ns2 are not shown: node ns2 is offline: unreachable')
  })

  it('filters by node', async () => {
    renderPage(`/alerts?node_id=${N2}`)
    await screen.findByText('Pool is full')
    expect(calls.list.mock.calls.at(-1)[0].node_id).toBe(N2)
  })

  it('lists open alerts by default with their counts', async () => {
    renderPage()
    const table = await screen.findByTestId('alerts-table')
    await waitFor(() => expect(within(table).getByText('Pool is full')).toBeInTheDocument())
    expect(calls.list).toHaveBeenCalledWith(expect.objectContaining({ state: 'open' }))
    expect(screen.getByText('Acknowledged', { selector: '*' })).toBeInTheDocument()
  })

  it('lists every state when the state filter is cleared', async () => {
    renderPage('/alerts?state=')
    await screen.findByText('Pool is full')
    expect(calls.list.mock.calls.at(-1)[0].state).toBeUndefined()
  })

  it('acknowledges with the comment typed', async () => {
    notify.showPrompt.mockResolvedValue('known, fixing')
    renderPage()
    await screen.findByText('Pool is full')
    fireEvent.click(screen.getAllByTestId('alert-row-ack')[0])
    await waitFor(() => expect(calls.ack).toHaveBeenCalledWith('A1', 'known, fixing'))
    expect(notify.showSuccess).toHaveBeenCalled()
  })

  it('opens the alert of a notification link, even when the filters hide it, and says where it went', async () => {
    renderPage('/alerts?alert=A9')
    const detail = await screen.findByTestId('alert-detail')
    expect(detail).toHaveTextContent('daemon:bind')
    const notified = await within(detail).findByTestId('alert-notified')
    expect(notified.dataset.count).toBe('2')
    expect(notified).toHaveTextContent('Phone, On-call mail')
  })

  it('says when a linked alert no longer exists', async () => {
    renderPage('/alerts?alert=GONE')
    await waitFor(() => expect(notify.showInfo).toHaveBeenCalledWith('This alert no longer exists: it was resolved and purged'))
    expect(screen.queryByTestId('alert-detail')).toBeNull()
  })

  it('shows the notification mute above the table', async () => {
    mute = { until: '2026-10-28T12:00:00Z', comment: 'kernel upgrade', by: 'admin', at: '2026-10-28T10:00:00Z' }
    renderPage()
    expect(await screen.findByTestId('alerts-notify-muted')).toHaveTextContent('kernel upgrade')
  })

  it('links a failing channel alert to its channel', () => {
    expect(subjectLink({ subject: 'notify:01JCH' })).toEqual({ to: '/admin/notifications?channel=01JCH', label: 'openChannel' })
  })

  it('links the DDNS failover alerts and the D2 advice to the failover tab', () => {
    const tab = '/dhcp/v4/ddns?tab=failover'
    expect(subjectLink({ subject: 'ddns:_default/example.lan.' })).toEqual({ to: `${tab}&zone=_default%2Fexample.lan.`, label: 'openFailover' })
    expect(subjectLink({ subject: 'ddns:stale:internal/corp.example.lan.' }).to).toBe(`${tab}&zone=internal%2Fcorp.example.lan.`)
    expect(subjectLink({ subject: 'ddns:replay' })).toEqual({ to: tab, label: 'openFailover' })
    expect(subjectLink({ subject: 'd2:dns-servers' }).to).toBe(tab)
    expect(subjectLink({ subject: 'd2:updates' }).to).toBe('/dhcp/v4/ddns')
    expect(subjectLink({ subject: 'resolver:roots', details: { remediation: 'resolver_fallback' } })).toEqual({ to: '/dns/resolver?fallback=1', label: 'proposeFallback' })
    expect(subjectLink({ subject: 'resolver:cache', details: { per_minute: 150 } })).toEqual({ to: '/dns/resolver', label: 'openResolver' })
  })

  it('links the obsolete Kea series alert to the migration analysis', () => {
    expect(subjectLink({ subject: 'kea:series' })).toEqual({ to: '/install/kea-migration', label: 'openKeaMigration' })
  })

  it('links the IPv6 checks to the filtered IPv6 tab of Hosts', () => {
    expect(subjectLink({ subject: 'ipv6:aaaa:example.lan.' })).toEqual({ to: '/hosts?tab=ipv6&filter=missing_aaaa&zone=example.lan.', label: 'openIpv6' })
    expect(subjectLink({ subject: 'ipv6:stale:example.lan.' }).to).toBe('/hosts?tab=ipv6&filter=stale&zone=example.lan.')
    expect(subjectLink({ subject: 'ipv6:reverse:2001:db8::/64' })).toEqual({ to: '/dns/zones', label: null })
  })

  it('shows the detail with a link to the host', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('PTR of 192.0.2.106 names another host'))
    const detail = await screen.findByTestId('alert-detail')
    expect(within(detail).getByTestId('alert-open-subject')).toHaveTextContent('Open the host')
  })

  it('proposes the fallback only to who can plan it and while none is active', async () => {
    extra = [PROPOSING]
    const open = async () => {
      const view = renderPage()
      fireEvent.click(await screen.findByText('resolver p95 is slow'))
      const detail = await screen.findByTestId('alert-detail')
      return { view, detail }
    }
    let { view, detail } = await open()
    await waitFor(() => expect(within(detail).getByTestId('alert-open-subject')).toHaveTextContent('Propose the forwarder fallback'))
    view.unmount()
    resolverFallback = { id: 'F1', node_ids: [N1], forwarders: ['192.0.2.53'], until: '2026-10-24T12:00:00Z' }
    ;({ view, detail } = await open())
    await new Promise((r) => setTimeout(r, 20))
    expect(within(detail).getByTestId('alert-open-subject')).not.toHaveTextContent('Propose')
    view.unmount()
    resolverFallback = null
    canDns = false
    ;({ view, detail } = await open())
    await new Promise((r) => setTimeout(r, 20))
    expect(within(detail).getByTestId('alert-open-subject')).not.toHaveTextContent('Propose')
    expect(subjectLink(PROPOSING, { canProposeFallback: false })).toEqual({ to: '/dns/resolver', label: 'openResolver' })
    expect(subjectLink({ ...PROPOSING, state: 'resolved' })).toEqual({ to: '/dns/resolver', label: 'openResolver' })
  })

  it('says since when the distribution security data is unavailable', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('upstream kea4 2.6.3 is affected'))
    const detail = await screen.findByTestId('alert-detail')
    expect(within(detail).getByTestId('distro-data-unavailable')).toHaveTextContent('unavailable since')
    expect(within(detail).getByTestId('distro-data-unavailable')).toHaveTextContent('download deadline exceeded')
  })

  it('ignores the objects of an inconsistency with a mandatory comment', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('PTR of 192.0.2.106 names another host'))
    fireEvent.click(await screen.findByTestId('alert-ignore'))
    const dialog = await screen.findByTestId('ignore-dialog')
    fireEvent.click(within(dialog).getByRole('button', { name: 'Ignore' }))
    expect(await within(dialog).findByText('Say why the object is left as it is')).toBeInTheDocument()
    expect(calls.addException).not.toHaveBeenCalled()
    fireEvent.change(screen.getByTestId('ignore-comment'), { target: { value: 'printer has no reverse on purpose' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Ignore' }))
    await waitFor(() =>
      expect(calls.addException).toHaveBeenCalledWith({ kind: 'ptr_mismatch', key: '192.0.2.106|pc7.example.lan.', comment: 'printer has no reverse on purpose', summary: 'PTR of 192.0.2.106 names another host' }),
    )
    expect(notify.showSuccess).toHaveBeenCalledWith('Exception recorded')
  })

  it('offers no ignore for alerts that are not inconsistencies', async () => {
    renderPage()
    fireEvent.click(await screen.findByText('Pool is full'))
    await screen.findByTestId('alert-detail')
    expect(screen.queryByTestId('alert-ignore')).toBeNull()
  })

  it('runs a consistency pass and reports what it found', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('alerts-consistency'))
    await waitFor(() => expect(notify.showSuccess).toHaveBeenCalledWith(expect.stringContaining('3')))
    expect(calls.run).toHaveBeenCalled()
  })

  it('reports the consistency pass under StrictMode', async () => {
    render(
      <StrictMode>
        <MemoryRouter initialEntries={['/alerts']}>
          <AlertsPage />
        </MemoryRouter>
      </StrictMode>,
    )
    const button = await screen.findByTestId('alerts-consistency')
    fireEvent.click(button)
    await waitFor(() => expect(notify.showSuccess).toHaveBeenCalledWith(expect.stringContaining('3')))
    await waitFor(() => expect(screen.getByTestId('alerts-consistency')).not.toBeDisabled())
  })

  it('hides write actions without write:alerts', async () => {
    canWrite = false
    renderPage()
    await screen.findByText('Pool is full')
    expect(screen.queryByTestId('alerts-consistency')).toBeNull()
    expect(screen.queryByTestId('alert-row-ack')).toBeNull()
  })
})

describe('alert subjects', () => {
  it('leads to the host, zone or screen the alert is about', () => {
    expect(subjectLink({ subject: 'ip:2001:db8::1' }).to).toBe('/hosts?q=2001%3Adb8%3A%3A1')
    expect(subjectLink({ subject: 'name:pc1.example.lan./A' }).to).toBe('/hosts?q=pc1.example.lan')
    expect(subjectLink({ subject: 'zone:example.lan.@internal' }).to).toBe('/dns/zones/example.lan?view=internal')
    expect(subjectLink({ subject: 'ns-silent:example.lan@internal:ns3.example.lan.' }).to).toBe('/dns/zones/example.lan?view=internal')
    expect(subjectLink({ subject: 'ns-primary:2.0.192.in-addr.arpa' }).to).toBe('/dns/zones/2.0.192.in-addr.arpa')
    expect(subjectLink({ subject: 'kea6:subnet:1:pool:2001:db8::/64' }).to).toBe('/dhcp/v6/subnets')
    expect(subjectLink({ subject: 'peer:01JB' }).to).toBe('/nodes')
    expect(subjectLink({ subject: 'engine:bind' })).toBeNull()
  })

  it('lists the exception keys of an inconsistency', () => {
    const alert = { kind: 'ptr_mismatch', details: { exception_keys: ['192.0.2.60|a.example.lan.', '192.0.2.60|b.example.lan.'] } }
    expect(exceptionItems(alert, 'title')).toEqual([
      { kind: 'ptr_mismatch', key: '192.0.2.60|a.example.lan.', summary: '192.0.2.60|a.example.lan.' },
      { kind: 'ptr_mismatch', key: '192.0.2.60|b.example.lan.', summary: '192.0.2.60|b.example.lan.' },
    ])
    expect(exceptionItems({ kind: 'pool_full', details: { exception_keys: ['x'] } })).toEqual([])
    expect(exceptionItems({ kind: 'duplicate_ip', details: {} })).toEqual([])
  })

  it('offers the node key of a health check alert, never of an outage', () => {
    const disk = { kind: 'disk_space', details: { exception_keys: ['n1|disk:/srv/archive'] } }
    expect(exceptionItems(disk, 'Free space on /srv/archive')).toEqual([
      { kind: 'disk_space', key: 'n1|disk:/srv/archive', summary: 'Free space on /srv/archive' },
    ])
    expect(exceptionItems({ kind: 'ha_terminated', details: { exception_keys: ['n1|ha:kea4'] } })).toEqual([])
    expect(exceptionItems({ kind: 'restart_loop', details: { exception_keys: ['x'] } })).toEqual([])
  })

  it('reads the result step of a job', () => {
    expect(jobResult({ steps: [{ name: 'result', output: { found: 2 } }] })).toEqual({ found: 2 })
    expect(jobResult({ steps: [] })).toBeNull()
  })
})

describe('cluster origin helpers', () => {
  it('reads the node or the reporters of an alert', () => {
    expect(alertOrigin({ node_id: 'a', reported_by: ['a'] })).toEqual({ node: 'a', reporters: ['a'] })
    expect(alertOrigin({ node_id: null })).toEqual({ node: null, reporters: [] })
  })

  it('merges the unavailable nodes of the list and the summary', () => {
    const u = { node_id: 'b', name: 'ns2', error: 'down' }
    expect(unavailableNodes([u], [u], undefined)).toEqual([u])
    expect(unavailableNodes(null)).toEqual([])
  })
})
