// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import schema from '../../../mock/settingsSchema.json'
import { defaultsOf, setPath } from './settingsSchema'

let current = {}
const updateSettings = vi.fn()
vi.mock('../../services/api', () => {
  const api = {
    admin: {
      settingsSchema: async () => schema,
      settings: async () => current,
      updateSettings: (body) => updateSettings(body),
    },
  }
  return { api, default: api }
})
const showSuccess = vi.fn()
const showError = vi.fn()
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess, showError }) }))

const { default: SettingsPage } = await import('./SettingsPage')

const renderPage = (path = '/admin/settings') =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <SettingsPage />
    </MemoryRouter>,
  )

beforeEach(() => {
  current = setPath(defaultsOf(schema), 'rpz.categories', { malware: { level: 'normal' } })
  updateSettings.mockReset()
  updateSettings.mockImplementation(async (body) => {
    let out = current
    const walk = (node, prefix) => {
      for (const [k, v] of Object.entries(node)) {
        const key = prefix ? `${prefix}.${k}` : k
        if (v && typeof v === 'object' && !Array.isArray(v) && key !== 'dns.view_keys') walk(v, key)
        else out = setPath(out, key, v)
      }
    }
    walk(body, '')
    current = out
    return out
  })
  showSuccess.mockReset()
  showError.mockReset()
})

describe('SettingsPage', () => {
  it('shows one form per domain with units, defaults and help', async () => {
    renderPage()
    const auth = await screen.findByTestId('settings-auth')
    expect(within(auth).getByLabelText('Session lifetime (s)')).toHaveValue(43200)
    expect(within(auth).getByText(/= 12 h · Default: 43200/)).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('settings-tab-checks'))
    const checks = await screen.findByTestId('settings-checks')
    expect(within(checks).getByText('High availability')).toBeInTheDocument()
    expect(within(checks).getByLabelText('HA alert grace period (s)')).toHaveValue(45)
    expect(within(checks).getByText('Warn about Kea hooks no package owns')).toBeInTheDocument()
    expect(within(checks).getByLabelText('Clock skew critical (s)')).toHaveValue(30)
    expect(within(checks).getByLabelText('Certificate expiry warning (days)')).toHaveValue(30)
    expect(screen.queryByText('categories')).toBeNull() // managed by the RPZ screen
  })

  it('opens the section named in the address', async () => {
    renderPage('/admin/settings?section=rpz')
    const rpz = await screen.findByTestId('settings-rpz')
    expect(within(rpz).getByLabelText('Memory warning (%)')).toHaveValue(25)
  })

  it('refuses a warning above its critical value, then saves only the change', async () => {
    renderPage('/admin/settings?section=checks')
    const input = await screen.findByLabelText('Pool warning (%)')
    fireEvent.change(input, { target: { value: '99' } })
    expect(await screen.findByText('Must be lower than “Pool critical”')).toBeInTheDocument()
    expect(screen.getByTestId('settings-save')).toBeDisabled()
    expect(screen.getByTestId('settings-tab-checks').className).toMatch(/status-danger-text/)
    fireEvent.change(input, { target: { value: '90' } })
    fireEvent.change(screen.getByLabelText('DDNS error share (%)'), { target: { value: '2.5' } })
    expect(screen.getByTestId('settings-changes')).toHaveTextContent('2 changes')
    fireEvent.click(screen.getByTestId('settings-save'))
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith({ checks: { pool_warning_percent: 90, d2_error_percent: 2.5 } }))
    await waitFor(() => expect(showSuccess).toHaveBeenCalledWith('Settings saved'))
    expect(screen.getByTestId('settings-save')).toBeDisabled()
  })

  it('rejects an out of range value before the server sees it', async () => {
    renderPage('/admin/settings?section=checks')
    fireEvent.change(await screen.findByLabelText('HA alert grace period (s)'), { target: { value: '7200' } })
    expect(await screen.findByText('Between 0 and 3600')).toBeInTheDocument()
    expect(screen.getByTestId('settings-save')).toBeDisabled()
  })

  it('resets a field to its default', async () => {
    current = setPath(current, 'checks.ha_grace_seconds', 90)
    renderPage('/admin/settings?section=checks')
    fireEvent.click(await screen.findByTestId('setting-checks-ha_grace_seconds-reset'))
    expect(screen.getByLabelText('HA alert grace period (s)')).toHaveValue(45)
    fireEvent.click(screen.getByTestId('settings-save'))
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith({ checks: { ha_grace_seconds: 45 } }))
  })

  it('finds a setting across sections', async () => {
    renderPage()
    await screen.findByTestId('settings-auth')
    fireEvent.change(screen.getByTestId('settings-search'), { target: { value: 'grace' } })
    expect(await screen.findByLabelText('HA alert grace period (s)')).toBeInTheDocument()
    expect(screen.queryByTestId('settings-auth')).toBeNull()
    fireEvent.change(screen.getByTestId('settings-search'), { target: { value: 'zzz' } })
    expect(await screen.findByTestId('settings-no-match')).toBeInTheDocument()
  })

  it('edits the keys of the views and sends the whole table', async () => {
    current = setPath(current, 'dns.view_keys', { inside: 'ddi-inside', guest: 'guest-key' })
    renderPage('/admin/settings?section=dns')
    const editor = await screen.findByTestId('setting-dns-view_keys')
    const removes = within(editor).getAllByRole('button', { name: 'Remove' })
    fireEvent.click(removes[1])
    fireEvent.click(within(editor).getByTestId('view-key-add'))
    const views = within(editor).getAllByTestId('view-key-view')
    fireEvent.change(views[1], { target: { value: 'lab' } })
    fireEvent.change(within(editor).getAllByTestId('view-key-admin')[1], { target: { value: 'lab-admin' } })
    fireEvent.change(within(editor).getAllByTestId('view-key-read')[1], { target: { value: 'lab-read' } })
    fireEvent.click(screen.getByTestId('settings-save'))
    await waitFor(() => expect(updateSettings).toHaveBeenCalledWith({ dns: { view_keys: { inside: 'ddi-inside', lab: { admin: 'lab-admin', read: 'lab-read' } } } }))
  })

  it('shows the server refusal next to the field', async () => {
    updateSettings.mockImplementation(async () => {
      const err = new Error('invalid settings')
      err.errors = [{ field: 'collector.poll_seconds', message: 'refused by the server' }]
      throw err
    })
    renderPage('/admin/settings?section=collector')
    fireEvent.change(await screen.findByLabelText('Engine poll (s)'), { target: { value: '30' } })
    fireEvent.click(screen.getByTestId('settings-save'))
    expect(await screen.findByText('refused by the server')).toBeInTheDocument()
    expect(showError).toHaveBeenCalled()
  })
})
