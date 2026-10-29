// SPDX-License-Identifier: Apache-2.0
// Administration > IPv6 sources: settings, sources with state, poll status per node, effective
// prefixes; add, test, disable and remove a source; save the listed prefixes.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import '../../../i18n'

const db = vi.hoisted(() => ({ data: null, puts: [], tests: [], testAnswer: null }))

vi.mock('../../../services/api', () => {
  const api = {
    ipv6: {
      settings: async () => db.data,
      update: async (body) => {
        db.puts.push(body)
        if (body.sources) db.data = { ...db.data, prefixes: [...db.data.prefixes], sources: body.sources.map((s, i) => ({ id: s.id || `NEW${i}`, ...s, secrets: { api_key: true, api_secret: true } })) }
        if (body.prefixes) db.data = { ...db.data, prefixes: body.prefixes }
        return db.data
      },
      testSource: async (body) => {
        db.tests.push(body)
        return db.testAnswer
      },
    },
    nodes: { list: async () => ({ items: [{ peer: { id: 'N1', name: 'ns1' } }, { peer: { id: 'N2', name: 'ns2' } }] }) },
  }
  return { api, default: api }
})
vi.mock('../../../contexts/NotificationContext', () => ({
  useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn(), showInfo: vi.fn(), showToast: vi.fn() }),
}))

const { default: Ipv6SourcesPage } = await import('./Ipv6SourcesPage')

const router = { id: 'S1', type: 'opnsense', name: 'Router', url: 'https://router.example.lan', verify_tls: true, ca_pem: null, enabled: true, allow_http: false, exclude_macs: [], secrets: { api_key: true, api_secret: true } }
const base = () => ({
  sources: [router],
  prefixes: [],
  effective_prefixes: [{ prefix: '2001:db8::/64', from: 'reverse_zone' }, { prefix: '2001:db8:5::/64', from: 'interface' }],
  settings: { neighbors_enabled: true, poll_seconds: 300, stable_min_days: 8, stale_days: 14, auto_apply_enabled: false },
  status: [
    { source: 'neighbors', source_id: null, node_id: 'N1', last_poll: '2026-10-29T08:00:00Z', error: null, entries: 14 },
    { source: 'neighbors', source_id: null, node_id: 'N2', last_poll: null, error: 'node did not answer', entries: 0 },
    { source: 'opnsense', source_id: 'S1', node_id: 'N1', last_poll: '2026-10-29T08:00:00Z', error: null, entries: 37 },
  ],
})

const renderPage = () => render(<MemoryRouter><Ipv6SourcesPage /></MemoryRouter>)

beforeEach(() => {
  db.data = base()
  db.puts = []
  db.tests = []
  db.testAnswer = { ok: true, node_id: 'N1', entries: 37, sample: [{ mac: '02:00:5e:00:53:10', address: '2001:db8::5eff:fe00:5310', state: 'reachable' }] }
})

describe('Ipv6SourcesPage', () => {
  it('shows the settings, sources, poll status and effective prefixes', async () => {
    renderPage()
    expect(await screen.findByTestId('ipv6-neighbors')).toHaveTextContent('on')
    expect(screen.getByTestId('ipv6-sources')).toHaveTextContent('https://router.example.lan')
    const status = screen.getByTestId('ipv6-status')
    expect(within(status).getAllByTestId('ipv6-status-error').map((e) => e.textContent)).toEqual(['node did not answer'])
    expect(within(status).getAllByText('Router')).toHaveLength(1)
    expect(screen.getAllByTestId('ipv6-effective')[0].querySelectorAll('li')).toHaveLength(2)
    expect(screen.getByText('reverse zone')).toBeInTheDocument()
  })

  it('adds a source with its key and secret, tested before saving', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('ipv6-source-add'))
    const dialog = await screen.findByTestId('ipv6-source-dialog')
    fireEvent.click(within(dialog).getByTestId('ipv6-source-save'))
    expect(await within(dialog).findAllByText('Required')).not.toHaveLength(0)
    expect(db.puts).toEqual([])
    fireEvent.change(within(dialog).getByTestId('ipv6-source-name'), { target: { value: 'Edge' } })
    fireEvent.change(within(dialog).getByTestId('ipv6-source-url'), { target: { value: 'https://edge.example.lan' } })
    fireEvent.change(within(dialog).getByTestId('ipv6-source-key'), { target: { value: 'KEY' } })
    fireEvent.change(within(dialog).getByTestId('ipv6-source-secret'), { target: { value: 'SECRET' } })
    fireEvent.click(within(dialog).getByTestId('ipv6-source-test'))
    expect(await within(dialog).findByTestId('ipv6-source-test-result')).toHaveAttribute('data-ok', 'true')
    await waitFor(() => expect(within(dialog).getByTestId('ipv6-source-test-result')).toHaveTextContent('ns1'), { timeout: 3000 })
    expect(db.tests[0]).toMatchObject({ type: 'opnsense', url: 'https://edge.example.lan', secrets: { api_key: 'KEY', api_secret: 'SECRET' } })
    expect(db.tests[0].scope).toBeUndefined()
    fireEvent.click(within(dialog).getByTestId('ipv6-source-save'))
    await waitFor(() => expect(db.puts).toHaveLength(1))
    expect(db.puts[0].sources.map((s) => s.id)).toEqual(['S1', undefined])
    expect(db.puts[0].sources[0].secrets).toBeUndefined()
    expect(db.puts[0].sources[1]).toMatchObject({ name: 'Edge', secrets: { api_key: 'KEY', api_secret: 'SECRET' } })
    await waitFor(() => expect(screen.queryByTestId('ipv6-source-dialog')).toBeNull())
  })

  it('shows a failed test of a saved source on its row', async () => {
    db.testAnswer = { ok: false, node_id: 'N1', entries: 0, error: 'HTTP 401', sample: [] }
    renderPage()
    fireEvent.click(await screen.findByTestId('ipv6-source-row-test-button'))
    expect(await screen.findByTestId('ipv6-source-row-test')).toHaveTextContent('Failed: HTTP 401')
    expect(db.tests).toEqual([{ source_id: 'S1' }])
  })

  it('disables then removes a source through the whole list', async () => {
    renderPage()
    fireEvent.click(await screen.findByTestId('ipv6-source-toggle'))
    await waitFor(() => expect(db.puts[0].sources[0]).toMatchObject({ id: 'S1', enabled: false }))
    fireEvent.click(screen.getByTestId('ipv6-source-delete'))
    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    await waitFor(() => expect(db.puts[1]).toEqual({ sources: [] }))
  })

  it('keeps unsaved prefixes when a source write answers', async () => {
    renderPage()
    const input = await screen.findByTestId('ipv6-prefixes-input')
    fireEvent.change(input, { target: { value: '2001:db8:1::/64' } })
    fireEvent.click(screen.getByTestId('ipv6-source-toggle'))
    await waitFor(() => expect(db.puts).toHaveLength(1))
    await waitFor(() => expect(screen.getByTestId('ipv6-source-toggle')).toBeInTheDocument())
    expect(screen.getByTestId('ipv6-prefixes-input')).toHaveValue('2001:db8:1::/64')
  })

  it('validates and saves the listed prefixes', async () => {
    renderPage()
    const input = await screen.findByTestId('ipv6-prefixes-input')
    fireEvent.change(input, { target: { value: 'fe80::/10' } })
    expect(await screen.findByText(/Link-local and multicast are never watched/)).toBeInTheDocument()
    expect(screen.getByTestId('ipv6-prefixes-save')).toBeDisabled()
    fireEvent.change(input, { target: { value: '2001:db8:1::/64\nfd00:1::/48' } })
    fireEvent.click(screen.getByTestId('ipv6-prefixes-save'))
    await waitFor(() => expect(db.puts).toEqual([{ prefixes: ['2001:db8:1::/64', 'fd00:1::/48'] }]))
  })
})
