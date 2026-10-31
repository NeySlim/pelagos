// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { resetNodeNamesCache } from '../hooks/useNodeNames'
import { NodeLink } from './NodeLink'

vi.mock('../services/api', () => ({
  api: {
    nodes: {
      list: vi.fn().mockResolvedValue({
        items: [
          { peer: { id: 'n1', name: 'ns1.example.lan', web_url: 'https://ns1.example.lan:8443/' } },
          { peer: { id: 'n2', name: 'ns2.example.lan', web_url: null } },
          { peer: { id: 'n3', name: 'ns3.example.lan', web_url: 'javascript:alert(1)' } },
        ],
      }),
    },
  },
}))

const renderLink = (props) => render(<MemoryRouter><NodeLink {...props} /></MemoryRouter>)

describe('NodeLink', () => {
  beforeEach(() => resetNodeNamesCache())

  it('links a node with a web_url to its own UI in a new window', async () => {
    renderLink({ nodeId: 'n1' })
    const link = await screen.findByText('ns1.example.lan')
    expect(link).toHaveAttribute('href', 'https://ns1.example.lan:8443/')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link.getAttribute('rel')).toContain('noopener')
    expect(link).toHaveAttribute('title', 'https://ns1.example.lan:8443/')
  })

  it('links a node without web_url to the nodes page, found by name', async () => {
    renderLink({ name: 'ns2.example.lan' })
    const link = await screen.findByText('ns2.example.lan')
    expect(link).toHaveAttribute('href', '/nodes')
    expect(link).not.toHaveAttribute('target')
  })

  it('shows the host only in the short variant, the full URL in the title', async () => {
    renderLink({ nodeId: 'n1', short: true })
    const link = await screen.findByText('ns1')
    expect(link).toHaveAttribute('title', 'https://ns1.example.lan:8443/')
  })

  it('never links a web_url that is not http or https', async () => {
    renderLink({ nodeId: 'n3' })
    const link = await screen.findByText('ns3.example.lan')
    expect(link).toHaveAttribute('href', '/nodes')
    expect(link).not.toHaveAttribute('target')
    expect(link).not.toHaveAttribute('title')
  })

  it('falls back to the id of an unknown node', async () => {
    renderLink({ nodeId: 'n9' })
    expect(await screen.findByText('n9')).toHaveAttribute('href', '/nodes')
  })
})
