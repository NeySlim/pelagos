// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { CreateHostModal } from './CreateHostModal'
import { recordZoneNamesIn, zoneNamesIn, zoneViews } from './net'
import { api } from '../../services/api'

vi.mock('../../services/api', () => {
  const api = { hosts: { plan: vi.fn() } }
  return { api, default: api }
})

const zone = (name, view = '_default') => ({ zone: { name, view } })
const PLAIN = [zone('example.lan.'), zone('2.0.192.in-addr.arpa.')]
const VIEWS = [
  zone('example.lan.'), zone('2.0.192.in-addr.arpa.'),
  zone('example.lan.', 'internal'), zone('corp.example.lan.', 'internal'), zone('2.0.192.in-addr.arpa.', 'internal'),
]

const flow = { building: false, build: (fn) => fn() }

function renderModal(zones) {
  api.hosts.plan.mockResolvedValue({ id: 'P1' })
  render(<CreateHostModal subnets={[]} zones={zones} flow={flow} onClose={() => {}} />)
}

function fill() {
  fireEvent.change(screen.getByTestId('host-hostname'), { target: { value: 'printer2' } })
  fireEvent.change(screen.getByTestId('host-ip'), { target: { value: '192.0.2.42' } })
}

const submit = () => fireEvent.submit(screen.getByTestId('host-form'))

describe('view helpers', () => {
  it('list the views holding zones, the default view first', () => {
    expect(zoneViews(VIEWS)).toEqual(['_default', 'internal'])
    expect(zoneViews([])).toEqual([])
    expect(zoneNamesIn(VIEWS, 'internal')).toEqual(['example.lan.', 'corp.example.lan.', '2.0.192.in-addr.arpa.'])
    expect(zoneNamesIn([{ zone: { name: 'a.' } }], undefined)).toEqual(['a.'])
  })
})

describe('record zones', () => {
  it('leave out the zones no host record can go to', () => {
    const zones = [
      { zone: { name: 'example.lan.', kind: 'primary' } },
      { zone: { name: 'corp.example.lan.', kind: 'secondary' } },
      { zone: { name: 'example.com.', kind: 'forward' } },
      { zone: { name: '.', kind: 'hint' } },
      { zone: { name: 'localhost.', kind: 'primary' } },
      { zone: { name: 'rpz.example.lan.', kind: 'primary', role: 'policy' } },
    ]
    expect(recordZoneNamesIn(zones)).toEqual(['example.lan.', 'corp.example.lan.'])
  })

  it('says the reverse zone follows the address before one is typed', () => {
    renderModal(PLAIN)
    expect(screen.getByText('Deduced from the address')).toBeTruthy()
    fireEvent.change(screen.getByTestId('host-ip'), { target: { value: '198.51.100.7' } })
    expect(screen.getByText(/No reverse zone covers this address/)).toBeTruthy()
  })
})

describe('CreateHostModal views', () => {
  beforeEach(() => vi.clearAllMocks())

  it('hides the view pickers without views and sends no view', async () => {
    renderModal(PLAIN)
    expect(screen.queryByTestId('host-view')).toBeNull()
    expect(screen.queryByTestId('host-reverse-view')).toBeNull()
    fill()
    submit()
    await waitFor(() => expect(api.hosts.plan).toHaveBeenCalled())
    const body = api.hosts.plan.mock.calls[0][0]
    expect(body).not.toHaveProperty('view')
    expect(body).not.toHaveProperty('reverse_view')
    expect(body.reverse_zone).toBe('2.0.192.in-addr.arpa.')
  })

  it('defaults to the default view with the reverse view following it', async () => {
    renderModal(VIEWS)
    expect(screen.getByTestId('host-view')).toHaveValue('_default')
    expect(screen.getByTestId('host-reverse-view')).toHaveValue('')
    fill()
    submit()
    await waitFor(() => expect(api.hosts.plan).toHaveBeenCalled())
    const body = api.hosts.plan.mock.calls[0][0]
    expect(body).not.toHaveProperty('view')
    expect(body).not.toHaveProperty('reverse_view')
  })

  it('sends the chosen view, its zones, and an explicit reverse view', async () => {
    renderModal(VIEWS)
    fireEvent.change(screen.getByTestId('host-view'), { target: { value: 'internal' } })
    const zones = [...screen.getByTestId('host-zone').querySelectorAll('option')].map((o) => o.value)
    expect(zones).toEqual(['example.lan.', 'corp.example.lan.'])
    fireEvent.change(screen.getByTestId('host-zone'), { target: { value: 'corp.example.lan.' } })
    fireEvent.change(screen.getByTestId('host-reverse-view'), { target: { value: '_default' } })
    fill()
    submit()
    await waitFor(() => expect(api.hosts.plan).toHaveBeenCalled())
    expect(api.hosts.plan.mock.calls[0][0]).toMatchObject({ view: 'internal', reverse_view: '_default', zone: 'corp.example.lan.' })
  })
})
