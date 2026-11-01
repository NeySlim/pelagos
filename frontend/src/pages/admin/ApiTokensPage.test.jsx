// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import ApiTokensPage from './ApiTokensPage'
import { api } from '../../services/api'

vi.mock('../../contexts/NotificationContext', () => ({ useNotification: () => ({ showSuccess: vi.fn(), showError: vi.fn() }) }))
vi.mock('../../services/api', () => {
  const api = { admin: { tokens: vi.fn(), revokeToken: vi.fn() } }
  return { api, default: api }
})

describe('ApiTokensPage', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the error notice and no empty state when the load failed', async () => {
    api.admin.tokens.mockRejectedValue(Object.assign(new TypeError('Cannot read properties of undefined'), { status: 500 }))
    render(<ApiTokensPage />)
    expect(await screen.findByTestId('error-notice')).toBeInTheDocument()
    expect(screen.queryByTestId('admin-tokens-table')).toBeNull()
    expect(screen.queryByText('No API token')).toBeNull()
  })

  it('shows the expired badge once per token', async () => {
    api.admin.tokens.mockResolvedValue({ items: [{ id: 't1', username: 'alice', name: 'old', role: 'viewer', permissions: [], cidrs: [], expired: true, expires_at: '2026-01-01T00:00:00Z', created_at: '2025-10-01T00:00:00Z' }], meta: {} })
    render(<ApiTokensPage />)
    await screen.findByTestId('admin-token-name')
    expect(screen.getAllByText('Expired')).toHaveLength(1)
  })
})
