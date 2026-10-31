// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, renderHook, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import i18n from '../i18n'
import { useReadOnlyReason } from '../hooks/useReadOnlyReason'
import { ReadOnlyNote } from './ReadOnlyNote'

const auth = { permissions: ['read:dns.records'], node: { peer: { id: 'n1', name: 'ns1' } } }
vi.mock('../contexts/AuthContext', () => ({
  useAuth: () => ({
    ...auth,
    hasPermission: (p) => (Array.isArray(p) ? p : [p]).some((x) => auth.permissions.includes(x)),
  }),
}))
vi.mock('../services/api', () => ({
  api: { nodes: { list: vi.fn().mockResolvedValue({ items: [{ peer: { id: 'n2', name: 'ns2', web_url: 'https://ns2.example.lan/' } }] }) } },
}))

const renderNote = (props) => render(<MemoryRouter><ReadOnlyNote {...props} /></MemoryRouter>)

describe('ReadOnlyNote', () => {
  afterEach(() => i18n.changeLanguage('en'))

  it('names the missing permission', () => {
    renderNote({ permission: 'write:dns.records' })
    expect(screen.getByTestId('read-only-note')).toHaveTextContent('Read only: your roles do not have write:dns.records')
    expect(screen.getByTestId('read-only-note')).toHaveAttribute('data-reason', 'permission')
  })

  it('lists several permissions and speaks French', async () => {
    await i18n.changeLanguage('fr')
    renderNote({ permission: ['write:dhcp', 'ops:dhcp'] })
    expect(screen.getByTestId('read-only-note')).toHaveTextContent("Lecture seule : vos rôles n'ont pas write:dhcp ou ops:dhcp")
  })

  it('points to the node that owns the action', async () => {
    renderNote({ reason: 'node', nodeId: 'n2' })
    expect(screen.getByTestId('read-only-note')).toHaveTextContent('This action is done on')
    expect(await screen.findByText('ns2')).toHaveAttribute('href', 'https://ns2.example.lan/')
  })

  it('takes the caller text for a state or custom reason', () => {
    const { rerender } = renderNote({ reason: 'state' })
    expect(screen.getByTestId('read-only-note')).toHaveTextContent('Read only in the current state')
    rerender(<MemoryRouter><ReadOnlyNote reason="custom">The zone is a secondary</ReadOnlyNote></MemoryRouter>)
    expect(screen.getByTestId('read-only-note')).toHaveTextContent('The zone is a secondary')
  })
})

describe('useReadOnlyReason', () => {
  it('answers permission, node or null', () => {
    expect(renderHook(() => useReadOnlyReason('write:dns.records')).result.current).toBe('permission')
    expect(renderHook(() => useReadOnlyReason('read:dns.records')).result.current).toBeNull()
    expect(renderHook(() => useReadOnlyReason(['write:dns.records', 'read:dns.records'])).result.current).toBeNull()
    expect(renderHook(() => useReadOnlyReason('read:dns.records', { nodeId: 'n2' })).result.current).toBe('node')
    expect(renderHook(() => useReadOnlyReason(null, { nodeId: 'n1' })).result.current).toBeNull()
  })
})
