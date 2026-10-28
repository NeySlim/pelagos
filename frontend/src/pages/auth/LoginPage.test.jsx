// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LoginPage from './LoginPage'
import { api } from '../../services/api'
import { getCredential } from '../../lib/webauthn'

const login = vi.fn()
const loginWithKey = vi.fn()
const navigate = vi.fn()
vi.mock('react-router-dom', async (orig) => ({ ...(await orig()), useNavigate: () => navigate }))
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ login, loginWithKey }) }))
vi.mock('../../contexts/ThemeContext', () => ({ useTheme: () => ({ effects: 'none' }) }))
vi.mock('../../stores/preferencesStore', () => ({ persistPreference: vi.fn() }))
vi.mock('../../lib/webauthn', async (orig) => ({ ...(await orig()), webauthnSupported: () => true, getCredential: vi.fn() }))
vi.mock('../../services/api', () => {
  const api = { auth: { webauthnSite: vi.fn(), passkeyOptions: vi.fn() } }
  return { api, default: api }
})

const problem = (code, extra = {}) => Object.assign(new Error(code), { code, problem: { code, ...extra } })
const OPTIONS = { challenge: 'AQ', allowCredentials: [{ type: 'public-key', id: 'k1' }] }

function fill() {
  fireEvent.change(screen.getByTestId('login-username'), { target: { value: 'alice' } })
  fireEvent.change(screen.getByTestId('login-password'), { target: { value: 'pw' } })
  fireEvent.click(screen.getByTestId('login-submit'))
}

describe('LoginPage with security keys', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.auth.webauthnSite.mockResolvedValue({ available: true, rp_id: 'example.lan', reason: null })
  })

  it('asks the key after the password and signs in', async () => {
    login.mockRejectedValue(problem('second_factor_required', { methods: ['webauthn'], ceremony: 'c1', options: OPTIONS }))
    getCredential.mockResolvedValue({ id: 'k1' })
    loginWithKey.mockResolvedValue({})
    render(<MemoryRouter><LoginPage /></MemoryRouter>)
    fill()
    await waitFor(() => expect(loginWithKey).toHaveBeenCalledWith('c1', { id: 'k1' }))
    expect(getCredential).toHaveBeenCalledWith(OPTIONS)
    expect(navigate).toHaveBeenCalledWith('/', { replace: true })
  })

  it('offers the TOTP code instead and retries the key with a new challenge', async () => {
    login.mockRejectedValue(problem('second_factor_required', { methods: ['webauthn', 'totp'], ceremony: 'c1', options: OPTIONS }))
    getCredential.mockRejectedValueOnce(Object.assign(new Error('closed'), { name: 'NotAllowedError' }))
    render(<MemoryRouter><LoginPage /></MemoryRouter>)
    fill()
    expect(await screen.findByText('The security key prompt was closed')).toBeInTheDocument()
    expect(screen.getByTestId('login-key-step')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('login-use-totp'))
    expect(screen.getByTestId('login-totp')).toBeInTheDocument()
  })

  it('names the domain of keys that cannot answer here', async () => {
    login.mockRejectedValue(problem('second_factor_required', { methods: [], rp_ids: ['example.lan'] }))
    render(<MemoryRouter><LoginPage /></MemoryRouter>)
    fill()
    expect(await screen.findByTestId('login-error')).toHaveTextContent('example.lan')
  })

  it('signs in with a passkey without a password', async () => {
    api.auth.passkeyOptions.mockResolvedValue({ ceremony: 'p1', options: { challenge: 'AQ' } })
    getCredential.mockResolvedValue({ id: 'k9' })
    loginWithKey.mockResolvedValue({})
    render(<MemoryRouter><LoginPage /></MemoryRouter>)
    fireEvent.click(await screen.findByTestId('login-passkey'))
    await waitFor(() => expect(loginWithKey).toHaveBeenCalledWith('p1', { id: 'k9' }))
  })

  it('hides the passkey button where keys cannot run', async () => {
    api.auth.webauthnSite.mockResolvedValue({ available: false, rp_id: null, reason: 'ip_address' })
    render(<MemoryRouter><LoginPage /></MemoryRouter>)
    await waitFor(() => expect(api.auth.webauthnSite).toHaveBeenCalled())
    expect(screen.queryByTestId('login-passkey')).toBeNull()
  })
})
