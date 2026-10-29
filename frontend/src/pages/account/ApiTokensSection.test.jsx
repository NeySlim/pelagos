// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ApiTokensSection } from './ApiTokensSection'
import { api } from '../../services/api'
import { getCredential } from '../../lib/webauthn'

vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../lib/webauthn', async (orig) => ({ ...(await orig()), getCredential: vi.fn() }))
vi.mock('../../services/api', () => {
  const api = { auth: { tokens: vi.fn(), tokenChallenge: vi.fn(), tokenCreate: vi.fn(), tokenRevoke: vi.fn() } }
  return { api, default: api }
})

const Section = ({ children, testId }) => <div data-testid={testId}>{children}</div>
const TOKEN = { id: 't1', name: 'monitor', role: 'viewer', permissions: ['read:dns'], cidrs: [], expires_at: '2027-01-27T09:00:00Z', expired: false, last_used_at: '2026-10-29T09:00:00Z', last_used_node: 'ns2' }

describe('ApiTokensSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.auth.tokens.mockResolvedValue({ items: [TOKEN], meta: { unavailable: [] } })
  })

  it('creates a token behind a fresh key assertion and shows the secret once', async () => {
    api.auth.tokenChallenge.mockResolvedValue({ methods: ['webauthn'], ceremony: 'c1', options: { challenge: 'AQ' } })
    getCredential.mockResolvedValue({ id: 'k1' })
    api.auth.tokenCreate.mockResolvedValue({ token: 'pel_0123456789abcdef_secret', item: { ...TOKEN, id: 't2', name: 'ci' } })
    render(<ApiTokensSection Section={Section} />)
    expect(await screen.findByTestId('token-name')).toHaveTextContent('monitor')
    expect(screen.getByText(/on ns2/)).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('token-add-submit'))
    expect(await screen.findByTestId('token-error')).toHaveTextContent('A name is required')
    fireEvent.change(screen.getByTestId('token-name-input'), { target: { value: 'ci' } })
    fireEvent.change(screen.getByTestId('token-cidrs-input'), { target: { value: '192.0.2.0/24, 2001:db8::/64' } })
    fireEvent.click(screen.getByTestId('token-add-submit'))
    await waitFor(() =>
      expect(api.auth.tokenCreate).toHaveBeenCalledWith({
        name: 'ci',
        role: 'viewer',
        expires_days: 90,
        cidrs: ['192.0.2.0/24', '2001:db8::/64'],
        ceremony: 'c1',
        credential: { id: 'k1' },
      }),
    )
    expect(getCredential).toHaveBeenCalledWith({ challenge: 'AQ' })
    expect(await screen.findByTestId('token-secret')).toHaveTextContent('pel_0123456789abcdef_secret')
  })

  it('asks for a one-time code when TOTP is the only factor', async () => {
    api.auth.tokenChallenge.mockResolvedValue({ methods: ['totp'] })
    api.auth.tokenCreate.mockResolvedValue({ token: 'pel_x', item: TOKEN })
    render(<ApiTokensSection Section={Section} />)
    fireEvent.change(await screen.findByTestId('token-name-input'), { target: { value: 'ci' } })
    fireEvent.click(screen.getByTestId('token-add-submit'))
    fireEvent.change(await screen.findByTestId('token-code-input'), { target: { value: '123456' } })
    fireEvent.click(screen.getByTestId('token-add-submit'))
    await waitFor(() => expect(api.auth.tokenCreate).toHaveBeenCalledWith(expect.objectContaining({ totp_code: '123456' })))
    expect(getCredential).not.toHaveBeenCalled()
  })

  it('explains that a second factor is needed', async () => {
    api.auth.tokenChallenge.mockRejectedValue(Object.assign(new Error('x'), { code: 'conflict', problem: { reason: 'no_second_factor' } }))
    render(<ApiTokensSection Section={Section} />)
    fireEvent.change(await screen.findByTestId('token-name-input'), { target: { value: 'ci' } })
    fireEvent.click(screen.getByTestId('token-add-submit'))
    expect(await screen.findByTestId('token-error')).toHaveTextContent('Register a security key or enable TOTP first')
  })

  it('revokes a token after confirmation', async () => {
    api.auth.tokenRevoke.mockResolvedValue(null)
    render(<ApiTokensSection Section={Section} />)
    fireEvent.click(await screen.findByTestId('token-revoke-open'))
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))
    await waitFor(() => expect(api.auth.tokenRevoke).toHaveBeenCalledWith('t1'))
  })
})
