// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { GlobalSearch } from './GlobalSearch'
import { useSearchShortcut } from '../hooks/useGlobalSearch'

const query = vi.fn()
const openDetail = vi.fn()
vi.mock('../services/api', () => ({ api: { search: { query: (...a) => query(...a) } } }))
vi.mock('./FloatingDetailWindow', () => ({ useOpenDetail: () => openDetail }))
let allowed = ['read:hosts']
vi.mock('../contexts/AuthContext', () => ({ useAuth: () => ({ hasPermission: (p) => allowed.includes(p) }) }))

const answer = {
  q: 'ab',
  results: {
    hosts: [{ kind: 'host', id: 'mac:02:00:5e:00:00:01', label: 'pc1.example.lan', sublabel: '192.0.2.10 02:00:5e:00:00:01', route: '/hosts?q=pc1.example.lan' }],
    zones: [{ kind: 'zone', id: 'example.lan', label: 'example.lan.', sublabel: 'primary', route: '/dns/zones/example.lan' }],
    records: [], leases: [], reservations: [], alerts: [], nodes: [], networks: [],
  },
  totals: { hosts: 3, zones: 1 },
  errors: {},
}

function Where() {
  const loc = useLocation()
  return <span data-testid="where">{loc.pathname + loc.search}</span>
}

function Harness() {
  return (
    <MemoryRouter>
      <GlobalSearch open onOpenChange={vi.fn()} />
      <Where />
    </MemoryRouter>
  )
}

const type = (value) => fireEvent.change(screen.getByTestId('global-search-input'), { target: { value } })

describe('GlobalSearch', () => {
  beforeEach(() => {
    query.mockReset()
    openDetail.mockReset()
    query.mockResolvedValue(answer)
  })

  it('waits for two characters, then lists the groups', async () => {
    render(<Harness />)
    type('a')
    expect(screen.getByTestId('global-search-status')).toHaveTextContent('at least 2')
    expect(query).not.toHaveBeenCalled()
    type('ab')
    expect(await screen.findAllByTestId('search-result')).toHaveLength(2)
    expect(query).toHaveBeenCalledWith('ab')
    expect(screen.getByRole('group', { name: 'Hosts' })).toBeInTheDocument()
    expect(screen.getByText('2 more')).toBeInTheDocument()
  })

  it('moves with the arrows through aria-activedescendant and opens with Enter', async () => {
    render(<Harness />)
    type('ab')
    const options = await screen.findAllByRole('option')
    const input = screen.getByRole('combobox')
    expect(input).toHaveAttribute('aria-activedescendant', options[0].id)
    expect(options[0]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    expect(input).toHaveAttribute('aria-activedescendant', options[1].id)
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    expect(input).toHaveAttribute('aria-activedescendant', options[0].id)
    fireEvent.keyDown(input, { key: 'ArrowUp' })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(screen.getByTestId('where')).toHaveTextContent('/dns/zones/example.lan')
    expect(openDetail).not.toHaveBeenCalled()
  })

  it('opens a host sheet over the filtered list', async () => {
    render(<Harness />)
    type('ab')
    fireEvent.click((await screen.findAllByRole('option'))[0])
    expect(screen.getByTestId('where')).toHaveTextContent('/hosts?q=pc1.example.lan')
    expect(openDetail).toHaveBeenCalledWith('host', 'mac:02:00:5e:00:00:01', { title: 'pc1.example.lan', subtitle: '192.0.2.10 02:00:5e:00:00:01' })
  })

  it('says so when nothing matches, and shows a failure with its retry', async () => {
    query.mockResolvedValueOnce({ q: 'zz', results: {}, totals: {}, errors: {} })
    render(<Harness />)
    type('zz')
    await waitFor(() => expect(screen.getByTestId('global-search-status')).toHaveTextContent('Nothing found for "zz"'))
    query.mockRejectedValueOnce(Object.assign(new Error('boom'), { status: 503 }))
    type('zy')
    expect(await screen.findByTestId('error-notice')).toBeInTheDocument()
    query.mockResolvedValueOnce(answer)
    fireEvent.click(screen.getByTestId('error-retry'))
    expect(await screen.findAllByTestId('search-result')).toHaveLength(2)
  })

  it('ignores a slow answer that a newer query superseded', async () => {
    let slow
    query.mockImplementationOnce(() => new Promise((r) => { slow = r }))
    render(<Harness />)
    type('ab')
    await waitFor(() => expect(query).toHaveBeenCalledTimes(1))
    query.mockResolvedValueOnce({ ...answer, results: { ...answer.results, hosts: [], zones: [] }, totals: {} })
    type('abc')
    await waitFor(() => expect(query).toHaveBeenCalledTimes(2))
    await act(async () => slow(answer))
    expect(screen.queryAllByTestId('search-result')).toHaveLength(0)
  })
})

describe('useSearchShortcut', () => {
  function Probe({ onOpen }) {
    useSearchShortcut(onOpen)
    return <input data-testid="field" />
  }

  it('opens on Ctrl+K and on "/", but not while typing', () => {
    const onOpen = vi.fn()
    render(<Probe onOpen={onOpen} />)
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true })
    expect(onOpen).toHaveBeenCalledTimes(1)
    fireEvent.keyDown(window, { key: '/' })
    expect(onOpen).toHaveBeenCalledTimes(2)
    fireEvent.keyDown(screen.getByTestId('field'), { key: '/' })
    expect(onOpen).toHaveBeenCalledTimes(2)
    fireEvent.keyDown(window, { key: 'k' })
    expect(onOpen).toHaveBeenCalledTimes(2)
  })

  it('uses Cmd+K only on a Mac', () => {
    const spy = vi.spyOn(navigator, 'platform', 'get').mockReturnValue('MacIntel')
    const onOpen = vi.fn()
    render(<Probe onOpen={onOpen} />)
    fireEvent.keyDown(window, { key: 'k', ctrlKey: true })
    expect(onOpen).not.toHaveBeenCalled()
    fireEvent.keyDown(window, { key: 'k', metaKey: true })
    expect(onOpen).toHaveBeenCalledTimes(1)
    spy.mockRestore()
  })
})
