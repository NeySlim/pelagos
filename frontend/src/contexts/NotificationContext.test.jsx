// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { NotificationProvider, useNotification } from './NotificationContext'

function Trigger() {
  const { showSuccess } = useNotification()
  return <button type="button" onClick={() => showSuccess('Saved')}>go</button>
}

afterEach(() => vi.restoreAllMocks())

describe('NotificationContext', () => {
  it('closes a toast through one button, never a button inside a button', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})
    render(
      <NotificationProvider>
        <Trigger />
      </NotificationProvider>,
    )
    fireEvent.click(screen.getByText('go'))
    const close = await screen.findByTestId('toast-close')
    expect(close.tagName).toBe('BUTTON')
    expect(close.querySelector('button')).toBeNull()
    expect(errors.mock.calls.flat().join(' ')).not.toMatch(/cannot be a descendant|validateDOMNesting/)
    fireEvent.click(close)
    await waitFor(() => expect(screen.queryByText('Saved')).toBeNull())
  })
})
