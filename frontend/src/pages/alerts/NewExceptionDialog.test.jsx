// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { NewExceptionDialog } from './NewExceptionDialog'
import { keyProblem, keyExample, exceptionKinds } from './exceptionForm'

describe('exception keys', () => {
  it('checks the shape of each kind of key', () => {
    expect(keyProblem('ptr_mismatch', '')).toBe('required')
    expect(keyProblem('ptr_mismatch', 'mail.example.net.')).toBe('format')
    expect(keyProblem('ptr_mismatch', '192.0.2.90|mail.example.net.')).toBe(null)
    expect(keyProblem('record_without_lease', 'www.example.lan./A')).toBe(null)
    expect(keyProblem('record_without_lease', 'www.example.lan./MX')).toBe('format')
    expect(keyProblem('duplicate_ip', '2001:db8::5')).toBe(null)
    expect(keyProblem('disk_space', 'disk:/var/lib/pelagos')).toBe(null)
    expect(keyProblem('disk_space', 'two words')).toBe('format')
    expect(keyExample('reservation_mismatch')).toContain('|')
    expect(exceptionKinds()).toContain('cert_expiry')
    expect(exceptionKinds()).not.toContain('daemon_down')
  })
})

describe('NewExceptionDialog', () => {
  it('requires a well formed key and a comment, then creates the exception', async () => {
    const addFn = vi.fn(async (body) => ({ id: 'x', ...body }))
    const onDone = vi.fn()
    render(<NewExceptionDialog open onClose={() => {}} onDone={onDone} addFn={addFn} />)
    fireEvent.change(screen.getByTestId('new-exception-key'), { target: { value: 'mail.example.net.' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    expect(await screen.findByText('Expected like 192.0.2.90|mail.example.net.')).toBeInTheDocument()
    expect(screen.getByText('Say why the object is left as it is')).toBeInTheDocument()
    expect(addFn).not.toHaveBeenCalled()
    fireEvent.change(screen.getByTestId('new-exception-key'), { target: { value: '192.0.2.90|mail.example.net.' } })
    fireEvent.change(screen.getByTestId('new-exception-comment'), { target: { value: 'relay of the provider' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(addFn).toHaveBeenCalledWith({ kind: 'ptr_mismatch', key: '192.0.2.90|mail.example.net.', comment: 'relay of the provider' }))
    expect(onDone).toHaveBeenCalled()
  })
})
