// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { createMemoryRouter, RouterProvider } from 'react-router-dom'
import { isChunkError, retryImport } from './lazyPage'
import { RouteError } from '../components/RouteError'

const chunkError = () => new TypeError('Failed to fetch dynamically imported module: https://ns1.example.lan/assets/OpsPage-x.js')

describe('retryImport', () => {
  it('imports again after a failure', async () => {
    const load = vi.fn().mockRejectedValueOnce(chunkError()).mockResolvedValue({ default: 'Page' })
    await expect(retryImport(load, [1, 1])).resolves.toEqual({ default: 'Page' })
    expect(load).toHaveBeenCalledTimes(2)
  })

  it('gives up with the last error', async () => {
    const load = vi.fn().mockRejectedValue(chunkError())
    await expect(retryImport(load, [1, 1])).rejects.toThrow('dynamically imported module')
    expect(load).toHaveBeenCalledTimes(3)
  })

  it('knows the chunk errors of Chrome, Safari and Firefox', () => {
    expect(isChunkError(chunkError())).toBe(true)
    expect(isChunkError(new TypeError('Importing a module script failed.'))).toBe(true)
    expect(isChunkError(new TypeError('error loading dynamically imported module'))).toBe(true)
    expect(isChunkError(new Error('x is undefined'))).toBe(false)
  })
})

describe('RouteError', () => {
  function renderWith(error) {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    global.fetch = vi.fn(() => new Promise(() => {}))
    const Boom = () => {
      throw error
    }
    const router = createMemoryRouter([{ path: '*', element: <Boom />, errorElement: <RouteError /> }])
    render(<RouterProvider router={router} />)
  }

  it('waits for the node and reloads when a page chunk could not be fetched', () => {
    renderWith(chunkError())
    expect(screen.getByText('Trying to reconnect...')).toBeInTheDocument()
    expect(global.fetch).toHaveBeenCalledWith('/api/v1/health', { cache: 'no-store' })
  })

  it('offers a reload for any other error', () => {
    renderWith(new Error('x is undefined'))
    expect(screen.getByTestId('route-error')).toHaveTextContent('Something went wrong')
    expect(screen.getByTestId('route-error-reload')).toHaveTextContent('Retry')
  })
})
