// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { UserKeys, WebAuthnStatus } from './UserKeys'
import { api } from '../../services/api'

vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../services/api', () => {
  const api = { admin: { webauthn: vi.fn(), userKeys: vi.fn(), removeUserKey: vi.fn(), removeUserKeys: vi.fn() } }
  return { api, default: api }
})

const KEYS = [
  { id: 'k1', name: 'YubiKey', rp_id: 'example.lan', created_at: '2026-10-28T09:00:00Z', last_used_at: null },
  { id: 'k2', name: 'Phone', rp_id: 'example.lan', created_at: '2026-10-28T09:00:00Z', last_used_at: null, backup_eligible: true },
]

describe('security keys administration', () => {
  beforeEach(() => vi.clearAllMocks())

  it('warns when the nodes share no domain', async () => {
    api.admin.webauthn.mockResolvedValue({ rp_id: null, source: 'request_host', nodes: [], warning: 'no_common_domain' })
    render(<WebAuthnStatus />)
    const banner = await screen.findByTestId('webauthn-status')
    expect(banner).toHaveAttribute('data-warning', 'no_common_domain')
    expect(banner).toHaveTextContent('share no DNS domain')
  })

  it('shows the common domain', async () => {
    api.admin.webauthn.mockResolvedValue({ rp_id: 'example.lan', source: 'common_domain', nodes: [], warning: null })
    render(<WebAuthnStatus />)
    expect(await screen.findByTestId('webauthn-status')).toHaveTextContent('example.lan, the domain the nodes share')
  })

  it('removes one key or all of them', async () => {
    api.admin.userKeys.mockResolvedValue({ items: KEYS })
    api.admin.removeUserKey.mockResolvedValue(null)
    api.admin.removeUserKeys.mockResolvedValue(null)
    const onChanged = vi.fn()
    render(<UserKeys user={{ id: 'u1', username: 'alice' }} onClose={vi.fn()} onChanged={onChanged} />)
    expect(await screen.findAllByTestId('user-key-row')).toHaveLength(2)
    fireEvent.click(screen.getAllByTestId('user-key-remove')[0])
    await waitFor(() => expect(api.admin.removeUserKey).toHaveBeenCalledWith('u1', 'k1'))
    fireEvent.click(screen.getByTestId('user-keys-remove-all'))
    await waitFor(() => expect(api.admin.removeUserKeys).toHaveBeenCalledWith('u1'))
    expect(onChanged).toHaveBeenCalledTimes(2)
  })
})
