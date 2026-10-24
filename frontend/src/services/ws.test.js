// SPDX-License-Identifier: Apache-2.0
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { createWsClient, WsState } from './ws'

class FakeSocket {
  static instances = []
  constructor(url) {
    this.url = url
    this.readyState = 0
    this.sent = []
    FakeSocket.instances.push(this)
  }
  send(data) {
    this.sent.push(JSON.parse(data))
  }
  close() {
    this.readyState = 3
    this.onclose?.()
  }
  open() {
    this.readyState = 1
    this.onopen?.()
  }
  receive(obj) {
    this.onmessage?.({ data: JSON.stringify(obj) })
  }
  drop() {
    this.readyState = 3
    this.onclose?.()
  }
}

describe('WebSocket client', () => {
  beforeEach(() => {
    FakeSocket.instances = []
    vi.useFakeTimers()
  })
  afterEach(() => vi.useRealTimers())

  it('subscribes to the topics in use and dispatches messages', () => {
    const client = createWsClient({ url: 'ws://test/api/v1/ws', WebSocketImpl: FakeSocket })
    const alerts = vi.fn()
    const all = vi.fn()
    client.on('alerts', alerts)
    client.on('*', all)
    client.connect()
    const socket = FakeSocket.instances[0]
    expect(client.state).toBe(WsState.CONNECTING)
    socket.open()
    expect(client.state).toBe(WsState.CONNECTED)
    expect(socket.sent).toEqual([{ action: 'subscribe', topics: ['alerts'] }])

    socket.receive({ topic: 'alerts', event: 'opened', data: { id: 'a1' } })
    socket.receive({ topic: 'ha', event: 'state', data: {} })
    socket.receive('not json')
    expect(alerts).toHaveBeenCalledTimes(1)
    expect(alerts.mock.calls[0][0].data.id).toBe('a1')
    expect(all).toHaveBeenCalledTimes(2)
  })

  it('counts subscribers per topic and unsubscribes on the last one', () => {
    const client = createWsClient({ url: 'ws://test', WebSocketImpl: FakeSocket })
    client.connect()
    const socket = FakeSocket.instances[0]
    socket.open()
    const off1 = client.on('jobs', () => {})
    const off2 = client.on('jobs', () => {})
    off1()
    off2()
    expect(socket.sent).toEqual([
      { action: 'subscribe', topics: ['jobs'] },
      { action: 'unsubscribe', topics: ['jobs'] },
    ])
  })

  it('pings on an interval and reconnects with backoff, resubscribing', () => {
    const client = createWsClient({ url: 'ws://test', WebSocketImpl: FakeSocket, pingInterval: 1000 })
    client.on('nodes', () => {})
    client.connect()
    FakeSocket.instances[0].open()
    vi.advanceTimersByTime(1000)
    expect(FakeSocket.instances[0].sent.at(-1)).toEqual({ action: 'ping' })

    FakeSocket.instances[0].drop()
    expect(client.state).toBe(WsState.DISCONNECTED)
    vi.advanceTimersByTime(1000)
    expect(FakeSocket.instances).toHaveLength(2)
    FakeSocket.instances[1].open()
    expect(FakeSocket.instances[1].sent[0]).toEqual({ action: 'subscribe', topics: ['nodes'] })
  })

  it('stays down after disconnect', () => {
    const client = createWsClient({ url: 'ws://test', WebSocketImpl: FakeSocket })
    client.connect()
    FakeSocket.instances[0].open()
    client.disconnect()
    vi.advanceTimersByTime(60000)
    expect(FakeSocket.instances).toHaveLength(1)
    expect(client.state).toBe(WsState.DISCONNECTED)
  })
})
