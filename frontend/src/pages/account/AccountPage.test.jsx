// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import AccountPage from './AccountPage'
import { api } from '../../services/api'

const updateUser = vi.fn()
const setThemeFamily = vi.fn()
let user
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ user, updateUser, node: { peer: { name: 'ns1' } } }) }))
vi.mock('../../contexts/ThemeContext', () => ({
  useTheme: () => ({ themeFamily: 'pelagic', setThemeFamily, mode: 'system', setMode: vi.fn(), themes: [{ id: 'pelagic', name: 'Pelagic', accent: '#2DD4BF' }, { id: 'sunset', name: 'Sunset', accent: '#F97316' }] }),
}))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../stores/preferencesStore', () => ({ persistPreference: vi.fn() }))
vi.mock('../../services/api', () => {
  const api = { auth: { changePassword: vi.fn(), totpEnroll: vi.fn(), totpConfirm: vi.fn(), totpDisable: vi.fn() } }
  return { api, default: api }
})

describe('AccountPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    user = { id: 'u1', username: 'alice', roles: ['dns-operator'], has_totp: false, must_change_password: false, last_login: null }
  })

  it('enrolls an authenticator with a QR code and a confirmation code', async () => {
    api.auth.totpEnroll.mockResolvedValue({ secret: 'JBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/Pelagos:alice?secret=JBSWY3DPEHPK3PXP&issuer=Pelagos' })
    api.auth.totpConfirm.mockResolvedValue(null)
    render(<AccountPage />)
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
    render(<AccountPage />)
    fireEvent.change(screen.getByTestId('totp-password'), { target: { value: 'secret' } })
    fireEvent.click(screen.getByTestId('totp-disable'))
    await waitFor(() => expect(api.auth.totpDisable).toHaveBeenCalledWith('secret'))
    expect(updateUser).toHaveBeenCalledWith({ has_totp: false })
  })

  it('checks the password policy before changing the password', async () => {
    api.auth.changePassword.mockResolvedValue(null)
    render(<AccountPage />)
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
    render(<AccountPage />)
    fireEvent.click(screen.getByText('Sunset'))
    expect(setThemeFamily).toHaveBeenCalledWith('sunset')
  })
})
