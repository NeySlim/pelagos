// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import i18n from '../i18n'
import { ApiError } from '../services/apiClient'
import { ErrorNotice } from './ErrorNotice'

describe('ErrorNotice', () => {
  afterEach(() => i18n.changeLanguage('en'))

  it('shows the error and retries on click', () => {
    const onRetry = vi.fn()
    render(<ErrorNotice error={new ApiError('Network error', { status: 0, code: 'network_error' })} onRetry={onRetry} />)
    expect(screen.getByRole('alert')).toHaveTextContent('The server cannot be reached')
    fireEvent.click(screen.getByTestId('error-retry'))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('speaks French', async () => {
    await i18n.changeLanguage('fr')
    render(<ErrorNotice error={new ApiError('Network error', { status: 0, code: 'network_error' })} onRetry={() => {}} />)
    expect(screen.getByTestId('error-retry')).toHaveTextContent('Réessayer')
    expect(screen.getByRole('alert')).toHaveTextContent('Le serveur')
  })

  it('renders nothing without an error and no button without onRetry', () => {
    const { container, rerender } = render(<ErrorNotice error={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<ErrorNotice error={new Error('boom')} prefix="Settings could not be read" />)
    expect(screen.getByRole('alert')).toHaveTextContent('Settings could not be read: boom')
    expect(screen.queryByTestId('error-retry')).toBeNull()
  })
})
