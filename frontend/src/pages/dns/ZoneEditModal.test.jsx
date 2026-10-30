// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

vi.mock('../../services/api', () => {
  const api = { dns: { dnssecPolicies: vi.fn().mockResolvedValue({ items: [], builtin: ['default'] }) } }
  return { api, default: api }
})

const { ZoneEditModal } = await import('./ZoneEditModal')
const { showsForwarding } = await import('./zoneTools')

const primary = { name: 'example.lan.', view: '_default', kind: 'primary', file: 'pelagos/zones/example.lan.db', forwarders: [], forward: null }

describe('ZoneEditModal', () => {
  it('a primary zone hides forwarding unless set, and shows its file read only', () => {
    render(<ZoneEditModal zone={primary} open onClose={vi.fn()} onPlan={vi.fn()} />)
    expect(screen.queryByTestId('zone-edit-forwarders')).not.toBeInTheDocument()
    const file = screen.getByTestId('zone-edit-file')
    expect(file).toHaveValue('pelagos/zones/example.lan.db')
    expect(file).toHaveAttribute('readonly')
  })

  it('forwarding stays where it applies or is already set', () => {
    expect(showsForwarding(primary)).toBe(false)
    expect(showsForwarding({ ...primary, forwarders: ['192.0.2.53'] })).toBe(true)
    expect(showsForwarding({ ...primary, kind: 'forward' })).toBe(true)
    expect(showsForwarding({ ...primary, kind: 'secondary' })).toBe(true)
  })
})
