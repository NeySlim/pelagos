// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import i18n from '../i18n'
import { ApiError } from '../services/apiClient'
import { errorKind } from '../hooks/useApi'
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
    expect(screen.getByTestId('error-notice-title')).toHaveTextContent('Le serveur ne répond pas')
    expect(screen.getByTestId('error-notice-details')).toHaveTextContent('Détails')
  })

  it('renders nothing without an error and no button without onRetry', () => {
    const { container, rerender } = render(<ErrorNotice error={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<ErrorNotice error={new Error('boom')} prefix="Settings could not be read" />)
    expect(screen.getByTestId('error-notice-title')).toHaveTextContent('Settings could not be read')
    expect(screen.getByTestId('error-notice-details')).toHaveTextContent('boom')
    expect(screen.queryByTestId('error-retry')).toBeNull()
  })

  it.each([
    [new ApiError('denied', { status: 403, code: 'forbidden' }), 'forbidden', 'You do not have the permission'],
    [new ApiError('gone', { status: 404, code: 'not_found' }), 'not_found', 'Not found'],
    [new ApiError('down', { status: 503, code: 'engine_unavailable' }), 'unavailable', 'The service is unavailable for now'],
    [new ApiError('bad gateway', { status: 502, code: 'error' }), 'unavailable', 'The service is unavailable for now'],
    [new TypeError("Cannot read properties of undefined (reading 'items')"), 'load_failed', 'The data could not be loaded'],
  ])('titles %s by its class and folds the technical text', (err, kind, title) => {
    render(<ErrorNotice error={err} />)
    expect(errorKind(err)).toBe(kind)
    expect(screen.getByRole('alert')).toHaveAttribute('data-kind', kind)
    expect(screen.getByTestId('error-notice-title')).toHaveTextContent(title)
    expect(screen.getByTestId('error-notice-title')).not.toHaveTextContent(err.message)
    const details = screen.getByTestId('error-notice-details')
    expect(details.tagName).toBe('DETAILS')
    expect(details).not.toHaveAttribute('open')
    expect(details).toHaveTextContent(err.message)
  })
})
