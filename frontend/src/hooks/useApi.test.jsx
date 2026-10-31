// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render, renderHook, screen } from '@testing-library/react'
import { ApiError } from '../services/apiClient'
import { RECONNECTED_EVENT, RETRY_DELAYS, useApi } from './useApi'
import { WebSocketProvider } from './useWebSocket'
import { WsState } from '../services/ws'

vi.mock('../contexts/AuthContext', () => ({ useAuth: () => ({ isAuthenticated: true }) }))

function transient() {
  const err = new ApiError('Network error', { status: 0, code: 'network_error' })
  err.retryable = true
  return err
}

describe('useApi retries transient GET failures', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('retries in the background with a growing delay and keeps the error until it succeeds', async () => {
    const fn = vi.fn().mockRejectedValueOnce(transient()).mockRejectedValueOnce(transient()).mockResolvedValue({ ok: 1 })
    const { result } = renderHook(() => useApi(fn))
    await act(async () => {})
    expect(result.current.error?.code).toBe('network_error')
    expect(fn).toHaveBeenCalledTimes(1)

    await act(async () => vi.advanceTimersByTime(RETRY_DELAYS[0]))
    expect(fn).toHaveBeenCalledTimes(2)
    expect(result.current.error).not.toBeNull()
    expect(result.current.loading).toBe(false)

    await act(async () => vi.advanceTimersByTime(RETRY_DELAYS[0]))
    expect(fn).toHaveBeenCalledTimes(2)
    await act(async () => vi.advanceTimersByTime(RETRY_DELAYS[1] - RETRY_DELAYS[0]))
    expect(fn).toHaveBeenCalledTimes(3)
    expect(result.current.error).toBeNull()
    expect(result.current.data).toEqual({ ok: 1 })

    await act(async () => vi.advanceTimersByTime(120000))
    expect(fn).toHaveBeenCalledTimes(3)
  })

  it.each([['focus'], ['online'], [RECONNECTED_EVENT]])('retries at once on %s', async (event) => {
    const fn = vi.fn().mockRejectedValueOnce(transient()).mockResolvedValue('back')
    const { result } = renderHook(() => useApi(fn))
    await act(async () => {})
    expect(result.current.error).not.toBeNull()
    await act(async () => window.dispatchEvent(new Event(event)))
    expect(fn).toHaveBeenCalledTimes(2)
    expect(result.current.data).toBe('back')
    expect(result.current.error).toBeNull()
  })

  it('never retries by itself an error that is not transient', async () => {
    const fn = vi.fn().mockRejectedValue(new ApiError('nope', { status: 403, code: 'forbidden' }))
    const { result } = renderHook(() => useApi(fn))
    await act(async () => {})
    await act(async () => window.dispatchEvent(new Event('focus')))
    await act(async () => vi.advanceTimersByTime(120000))
    expect(fn).toHaveBeenCalledTimes(1)
    expect(result.current.error.code).toBe('forbidden')
  })

  it('stops retrying once unmounted', async () => {
    const fn = vi.fn().mockRejectedValue(transient())
    const { unmount } = renderHook(() => useApi(fn))
    await act(async () => {})
    unmount()
    await act(async () => vi.advanceTimersByTime(120000))
    window.dispatchEvent(new Event('focus'))
    expect(fn).toHaveBeenCalledTimes(1)
  })
})

describe('WebSocketProvider', () => {
  function fakeClient() {
    const listeners = new Set()
    return {
      state: WsState.DISCONNECTED,
      onStateChange: (fn) => (listeners.add(fn), () => listeners.delete(fn)),
      on: () => () => {},
      connect: () => {},
      disconnect: () => {},
      ping: () => true,
      emit(next) {
        this.state = next
        listeners.forEach((fn) => fn(next))
      },
    }
  }

  it('announces a reconnection after a drop, not the first connection', async () => {
    const client = fakeClient()
    const seen = vi.fn()
    window.addEventListener(RECONNECTED_EVENT, seen)
    render(<WebSocketProvider client={client}><span>child</span></WebSocketProvider>)
    expect(screen.getByText('child')).toBeInTheDocument()
    act(() => client.emit(WsState.CONNECTING))
    act(() => client.emit(WsState.CONNECTED))
    expect(seen).not.toHaveBeenCalled()
    act(() => client.emit(WsState.DISCONNECTED))
    act(() => client.emit(WsState.CONNECTING))
    act(() => client.emit(WsState.CONNECTED))
    expect(seen).toHaveBeenCalledTimes(1)
    window.removeEventListener(RECONNECTED_EVENT, seen)
  })
})
