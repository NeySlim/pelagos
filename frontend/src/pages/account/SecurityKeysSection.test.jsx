// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SecurityKeysSection } from './SecurityKeysSection'
import { api } from '../../services/api'
import { createCredential } from '../../lib/webauthn'

const updateUser = vi.fn()
const checkSession = vi.fn()
vi.mock('../../contexts/AuthContext', () => ({ useAuth: () => ({ updateUser, checkSession }) }))
vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../lib/webauthn', async (orig) => ({ ...(await orig()), webauthnSupported: () => true, createCredential: vi.fn() }))
vi.mock('../../services/api', () => {
  const api = { auth: { keys: vi.fn(), keyRegisterOptions: vi.fn(), keyRegister: vi.fn(), keyRename: vi.fn(), keyRemove: vi.fn() } }
  return { api, default: api }
})

const Section = ({ children, testId }) => <div data-testid={testId}>{children}</div>
const KEY = { id: 'k1', name: 'YubiKey', rp_id: 'example.lan', created_at: '2026-10-28T09:00:00Z', last_used_at: null, backup_eligible: true, transports: ['usb'] }

describe('SecurityKeysSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.auth.keys.mockResolvedValue({ items: [KEY], available: true, rp_id: 'example.lan', reason: null })
  })

  it('lists keys and registers a new one through the browser', async () => {
    api.auth.keyRegisterOptions.mockResolvedValue({ ceremony: 'c1', options: { challenge: 'AQ' } })
    createCredential.mockResolvedValue({ id: 'k2' })
    api.auth.keyRegister.mockResolvedValue({ ...KEY, id: 'k2', name: 'Phone' })
    render(<SecurityKeysSection Section={Section} />)
    expect(await screen.findByTestId('key-name')).toHaveTextContent('YubiKey')
    expect(screen.getByText('Synced passkey')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('key-add-submit'))
    expect(await screen.findByText('Give the key a name')).toBeInTheDocument()
    fireEvent.change(screen.getByTestId('key-name-input'), { target: { value: 'Phone' } })
    fireEvent.click(screen.getByTestId('key-add-submit'))
    await waitFor(() => expect(api.auth.keyRegister).toHaveBeenCalledWith('c1', { id: 'k2' }, 'Phone'))
    expect(createCredential).toHaveBeenCalledWith({ challenge: 'AQ' })
    expect(updateUser).toHaveBeenCalledWith({ webauthn_count: 2 })
    expect(checkSession).toHaveBeenCalled()
  })

  it('says the prompt was closed instead of failing', async () => {
    api.auth.keyRegisterOptions.mockResolvedValue({ ceremony: 'c1', options: {} })
    createCredential.mockRejectedValue(Object.assign(new Error('no'), { name: 'NotAllowedError' }))
    render(<SecurityKeysSection Section={Section} />)
    fireEvent.change(await screen.findByTestId('key-name-input'), { target: { value: 'Phone' } })
    fireEvent.click(screen.getByTestId('key-add-submit'))
    expect(await screen.findByText('The browser prompt was closed')).toBeInTheDocument()
    expect(api.auth.keyRegister).not.toHaveBeenCalled()
  })

  it('renames and removes a key with the password', async () => {
    api.auth.keyRename.mockResolvedValue({ ...KEY, name: 'Desk' })
    api.auth.keyRemove.mockRejectedValueOnce(Object.assign(new Error('x'), { code: 'invalid_credentials' })).mockResolvedValueOnce(null)
    render(<SecurityKeysSection Section={Section} />)
    fireEvent.click(await screen.findByTestId('key-rename'))
    fireEvent.change(screen.getByTestId('key-rename-input'), { target: { value: 'Desk' } })
    fireEvent.submit(screen.getByTestId('key-rename-input').closest('form'))
    await waitFor(() => expect(api.auth.keyRename).toHaveBeenCalledWith('k1', 'Desk'))
    fireEvent.click(screen.getByTestId('key-remove-open'))
    fireEvent.change(await screen.findByTestId('key-remove-password'), { target: { value: 'bad' } })
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.auth.keyRemove).toHaveBeenCalledWith('k1', 'bad'))
    fireEvent.change(screen.getByTestId('key-remove-password'), { target: { value: 'good' } })
    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(api.auth.keyRemove).toHaveBeenCalledWith('k1', 'good'))
  })

  it('explains why keys cannot be added on this address', async () => {
    api.auth.keys.mockResolvedValue({ items: [], available: false, rp_id: null, reason: 'ip_address' })
    render(<SecurityKeysSection Section={Section} />)
    expect(await screen.findByTestId('key-unavailable')).toHaveTextContent('not its IP address')
    expect(screen.queryByTestId('key-add')).toBeNull()
  })
})
