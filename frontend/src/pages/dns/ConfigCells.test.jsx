// SPDX-License-Identifier: Apache-2.0
// Hint and forward zones show what the nodes compare (hints version, forwarders), not a serial.
import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import '../../i18n'
import { ConfigCells } from './common'

const nameOf = (id) => ({ A: 'ns1', B: 'ns2' })[id] || id

describe('ConfigCells', () => {
  it('shows each node hints version', () => {
    const row = { zone: { kind: 'hint' }, hints: { A: { related_version: 2024041801, sha256: 'aa' }, B: { related_version: 2026102801, sha256: 'aa' } } }
    render(<ConfigCells zone={row} nameOf={nameOf} divergent={false} />)
    const cells = screen.getAllByTestId('zone-config-cell').map((c) => c.textContent)
    expect(cells).toEqual(['ns12024041801', 'ns22026102801'])
  })

  it('shows forward mode and forwarders, flagged when they differ', () => {
    const row = { zone: { kind: 'forward' }, forwarders: { A: { forward: 'only', forwarders: ['192.0.2.53'] }, B: { forward: 'only', forwarders: ['192.0.2.54'] } } }
    render(<ConfigCells zone={row} nameOf={nameOf} divergent />)
    expect(screen.getAllByTestId('zone-config-cell')[1].textContent).toBe('ns2only 192.0.2.54')
    expect(screen.getByTestId('zone-config')).toHaveAttribute('title')
  })

  it('a dash when no node reported', () => {
    const { container } = render(<ConfigCells zone={{ zone: { kind: 'forward' } }} nameOf={nameOf} />)
    expect(container.textContent).toBe('-')
  })
})
