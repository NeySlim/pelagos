// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import AccountPage from './AccountPage'
import { api } from '../../services/api'

const updateUser = vi.fn()
const checkSession = vi.fn()
const setThemeFamily = vi.fn()
let user
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ user, updateUser, checkSession, node: { peer: { id: 'n1', name: 'ns1' } } }) }))
vi.mock('../../contexts/ThemeContext', () => ({
  useTheme: () => ({ themeFamily: 'pelagic', setThemeFamily, mode: 'system', setMode: vi.fn(), themes: [{ id: 'pelagic', name: 'Pelagic', accent: '#2DD4BF' }, { id: 'sunset', name: 'Sunset', accent: '#F97316' }] }),
}))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../stores/preferencesStore', () => ({ persistPreference: vi.fn() }))
vi.mock('../../services/api', () => {
  const api = { nodes: { list: vi.fn(() => Promise.resolve({ items: [{ peer: { id: 'n1', name: 'ns1' } }, { peer: { id: 'n2', name: 'ns2', web_url: 'https://ns2.example.lan:8443' } }] })) }, auth: { changePassword: vi.fn(), totpEnroll: vi.fn(), totpConfirm: vi.fn(), totpDisable: vi.fn(), keys: vi.fn(() => Promise.resolve({ items: [], available: false, reason: 'ip_address' })), tokens: vi.fn(() => Promise.resolve({ items: [], meta: {} })) } }
  return { api, default: api }
})

const Where = () => <span data-testid="where">{useLocation().hash}</span>
const renderPage = (hash = '') => render(<MemoryRouter initialEntries={[`/account${hash}`]}><AccountPage /><Where /></MemoryRouter>)
const openTab = (name) => fireEvent.mouseDown(screen.getByRole('tab', { name }), { button: 0 })

describe('AccountPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    user = { id: 'u1', username: 'alice', roles: ['dns-operator'], has_totp: false, must_change_password: false, last_login: null }
  })

  it('enrolls an authenticator with a QR code and a confirmation code', async () => {
    api.auth.totpEnroll.mockResolvedValue({ secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/Pelagos:alice?secret=JBSWY3DPEHPK3PXP&issuer=Pelagos' })
    api.auth.totpConfirm.mockResolvedValue(null)
    renderPage('#securite')
    fireEvent.click(screen.getByTestId('totp-enroll'))
    expect(await screen.findByTestId('totp-secret')).toHaveTextContent('JBSWY3DPEHPK3PXP')
    const qr = await screen.findByTestId('totp-qr')
    expect(qr.getAttribute('src')).toMatch(/^data:image\/svg\+xml/)
    fireEvent.change(screen.getByTestId('totp-code'), { target: { value: '12a34' } })
    fireEvent.click(screen.getByTestId('totp-confirm'))
    expect(await screen.findByText('Enter the 6 digits shown by the app')).toBeInTheDocument()
    expect(api.auth.totpConfirm).not.toHaveBeenCalled()
    fireEvent.change(screen.getByTestId('totp-code'), { target: { value: '123456' } })
    fireEvent.click(screen.getByTestId('totp-confirm'))
    await waitFor(() => expect(api.auth.totpConfirm).toHaveBeenCalledWith('123456'))
    expect(updateUser).toHaveBeenCalledWith({ has_totp: true })
  })

  it('turns two-factor off with the password', async () => {
    user = { ...user, has_totp: true }
    api.auth.totpDisable.mockResolvedValue(null)
    renderPage('#securite')
    fireEvent.change(screen.getByTestId('totp-password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByTestId('totp-disable'))
    await waitFor(() => expect(api.auth.totpDisable).toHaveBeenCalledWith('secret'))
    expect(updateUser).toHaveBeenCalledWith({ has_totp: false })
  })

  it('checks the password policy before changing the password', async () => {
    api.auth.changePassword.mockResolvedValue(null)
    renderPage('#securite')
    fireEvent.change(screen.getByTestId('password-current'), { target: { value: 'old' } })
    fireEvent.change(screen.getByTestId('password-new'), { target: { value: 'short' } })
    fireEvent.change(screen.getByTestId('password-confirm'), { target: { value: 'short' } })
    fireEvent.click(screen.getByTestId('password-submit'))
    expect(await screen.findByText('At least 12 characters')).toBeInTheDocument()
    fireEvent.change(screen.getByTestId('password-new'), { target: { value: 'Correct-horse-42' } })
    fireEvent.change(screen.getByTestId('password-confirm'), { target: { value: 'Correct-horse-42' } })
    fireEvent.click(screen.getByTestId('password-submit'))
    await waitFor(() => expect(api.auth.changePassword).toHaveBeenCalledWith('old', 'Correct-horse-42'))
  })

  it('switches the theme family from the swatches', () => {
    renderPage('#preferences')
    fireEvent.click(screen.getByText('Sunset'))
    expect(setThemeFamily).toHaveBeenCalledWith('sunset')
  })

  it('opens on the profile and lists the other nodes', async () => {
    renderPage()
    expect(screen.getByTestId('profile-node')).toHaveTextContent('ns1')
    const others = await screen.findByTestId('profile-other-nodes')
    expect(others).toHaveTextContent('ns2')
    expect(others).not.toHaveTextContent('ns1')
    expect(screen.getByTestId('profile-other-node')).toHaveAttribute('href', 'https://ns2.example.lan:8443')
    expect(screen.queryByTestId('account-password')).toBeNull()
  })

  it('moves from the token tab to the security tab when a second factor is missing', async () => {
    user = { ...user, webauthn_count: 0 }
    renderPage()
    openTab('API tokens')
    fireEvent.click(await screen.findByTestId('token-go-security'))
    expect(await screen.findByTestId('account-totp')).toBeInTheDocument()
  })

  it('keeps the tab in the URL hash and moves focus to Security from the token notice', async () => {
    user = { ...user, webauthn_count: 0 }
    renderPage()
    openTab('API tokens')
    expect(screen.getByTestId('where')).toHaveTextContent('#tokens')
    fireEvent.click(await screen.findByTestId('token-go-security'))
    expect(await screen.findByTestId('account-totp')).toBeInTheDocument()
    expect(screen.getByTestId('where')).toHaveTextContent('#security')
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Security' })).toHaveFocus())
  })

  it('stays on the security tab once the forced password change is done', async () => {
    user = { ...user, must_change_password: true }
    const view = renderPage()
    expect(await screen.findByTestId('account-password')).toBeInTheDocument()
    expect(screen.getByTestId('where')).toHaveTextContent('#security')
    user = { ...user, must_change_password: false }
    view.rerender(<MemoryRouter initialEntries={['/account#security']}><AccountPage /><Where /></MemoryRouter>)
    expect(screen.getByTestId('account-password')).toBeInTheDocument()
  })
})
