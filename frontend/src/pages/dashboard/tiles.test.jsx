// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { NodesTile, HaTile } from './tiles'

const node = (id, name, site) => ({ peer: { id, name, site, modules: {} }, is_self: id === 'N1', status: 'online', version: '0.4.0', config_version: 1, audit_count: 1 })
const wrap = (ui) => render(<MemoryRouter>{ui}</MemoryRouter>)

describe('NodesTile', () => {
  it('tags the site of each node once two sites exist', () => {
    wrap(<NodesTile summary={{ nodes: [node('N1', 'ns1', 'dc1'), node('N2', 'ns2', 'dc2')] }} />)
    expect(screen.getAllByTestId('node-site').map((e) => e.textContent)).toEqual(['dc1', 'dc2'])
  })

  it('shows no site for a single one', () => {
    wrap(<NodesTile summary={{ nodes: [node('N1', 'ns1', 'dc1'), node('N2', 'ns2', 'dc1')] }} />)
    expect(screen.queryByTestId('node-site')).toBeNull()
  })
})

describe('HaTile', () => {
  const ha = (state, partner) => ({ node_id: 'N1', family: 'v4', server_name: 'ns1', role: 'primary', state, partner: { in_touch: true, state: partner } })

  it('shortens long states and keeps the full one as title', () => {
    wrap(<HaTile summary={{ ha: [ha('hot-standby', 'in-maintenance')] }} nameOf={(id) => id} />)
    const row = screen.getByTestId('tile-ha-row')
    const hot = within(row).getByText('Hot')
    expect(hot.closest('[title]')).toHaveAttribute('title', 'Hot standby')
    const maint = within(row).getByText('Maint.')
    expect(maint.closest('[title]')).toHaveAttribute('title', 'In maintenance')
  })
})
