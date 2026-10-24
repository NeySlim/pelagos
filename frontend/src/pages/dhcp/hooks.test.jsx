// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

const mocks = vi.hoisted(() => ({ api: { nodes: { list: vi.fn() } } }))
vi.mock('../../services/api', () => ({ api: mocks.api, default: mocks.api }))

import { useNodeNames, resetNodeNameCache } from './hooks'

const NS1 = '01JB0000000000000000NS1AAA'

function Name() {
  const { nameOf } = useNodeNames()
  return <span data-testid="name">{nameOf(NS1)}</span>
}

beforeEach(() => {
  vi.clearAllMocks()
  resetNodeNameCache()
})

describe('useNodeNames', () => {
  it('does not cache a failed fetch', async () => {
    mocks.api.nodes.list.mockRejectedValueOnce(new Error('down'))
    const first = render(<Name />)
    await waitFor(() => expect(mocks.api.nodes.list).toHaveBeenCalledTimes(1))
    expect(screen.getByTestId('name')).toHaveTextContent(NS1)
    first.unmount()
    mocks.api.nodes.list.mockResolvedValueOnce({ items: [{ peer: { id: NS1, name: 'ns1' } }] })
    render(<Name />)
    await waitFor(() => expect(screen.getByTestId('name')).toHaveTextContent('ns1'))
    expect(mocks.api.nodes.list).toHaveBeenCalledTimes(2)
  })

  it('reuses the list within the TTL and fetches again after it', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(1_000_000)
    mocks.api.nodes.list.mockResolvedValue({ items: [{ peer: { id: NS1, name: 'ns1' } }] })
    const a = render(<Name />)
    await waitFor(() => expect(screen.getByTestId('name')).toHaveTextContent('ns1'))
    a.unmount()
    const b = render(<Name />)
    await waitFor(() => expect(screen.getByTestId('name')).toHaveTextContent('ns1'))
    expect(mocks.api.nodes.list).toHaveBeenCalledTimes(1)
    b.unmount()
    Date.now.mockReturnValue(1_000_000 + 61_000)
    render(<Name />)
    await waitFor(() => expect(mocks.api.nodes.list).toHaveBeenCalledTimes(2))
    Date.now.mockRestore()
  })
})
