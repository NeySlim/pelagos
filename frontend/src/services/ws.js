// SPDX-License-Identifier: Apache-2.0
// Plain WebSocket client for GET /api/v1/ws (architecture section 18): JSON text
// frames, topic subscriptions with reference counting, ping every 30 s and
// reconnection with capped backoff. No library: window.WebSocket is enough.

export const WS_TOPICS = ['alerts', 'ha', 'nodes', 'jobs', 'plans', 'audit', 'leases']

export const WsState = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  ERROR: 'error',
}

export function wsUrl(path = '/api/v1/ws') {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${window.location.host}${path}`
}

export function createWsClient({ url, pingInterval = 30000, maxBackoff = 15000, WebSocketImpl } = {}) {
  const Impl = WebSocketImpl || window.WebSocket
  const handlers = new Map() // topic -> Set(handler)
  const stateListeners = new Set()
  const topicCounts = new Map() // topic -> number of subscribers
  let socket = null
  let state = WsState.DISCONNECTED
  let wanted = false
  let attempts = 0
  let reconnectTimer = null
  let pingTimer = null

  const setState = (next) => {
    if (state === next) return
    state = next
    stateListeners.forEach((fn) => fn(state))
  }

  const send = (obj) => {
    if (socket && socket.readyState === 1) {
      socket.send(JSON.stringify(obj))
      return true
    }
    return false
  }

  const flushSubscriptions = () => {
    const topics = [...topicCounts.entries()].filter(([, n]) => n > 0).map(([t]) => t)
    if (topics.length) send({ action: 'subscribe', topics })
  }

  const clearTimers = () => {
    if (pingTimer) clearInterval(pingTimer)
    if (reconnectTimer) clearTimeout(reconnectTimer)
    pingTimer = null
    reconnectTimer = null
  }

  const scheduleReconnect = () => {
    if (!wanted || reconnectTimer) return
    const delay = Math.min(maxBackoff, 1000 * 2 ** Math.min(attempts, 4))
    attempts += 1
    reconnectTimer = setTimeout(() => {
      reconnectTimer = null
      open()
    }, delay)
  }

  const dispatch = (message) => {
    const topic = message?.topic
    if (!topic) return
    const set = handlers.get(topic)
    if (set) set.forEach((fn) => fn(message))
    const all = handlers.get('*')
    if (all) all.forEach((fn) => fn(message))
  }

  function open() {
    if (!wanted) return
    if (socket && (socket.readyState === 0 || socket.readyState === 1)) return
    setState(WsState.CONNECTING)
    let ws
    try {
      ws = new Impl(url || wsUrl())
    } catch {
      setState(WsState.ERROR)
      scheduleReconnect()
      return
    }
    socket = ws
    ws.onopen = () => {
      attempts = 0
      setState(WsState.CONNECTED)
      flushSubscriptions()
      if (pingTimer) clearInterval(pingTimer)
      pingTimer = setInterval(() => send({ action: 'ping' }), pingInterval)
    }
    ws.onmessage = (event) => {
      let message
      try {
        message = JSON.parse(event.data)
      } catch {
        return
      }
      dispatch(message)
    }
    ws.onerror = () => {
      setState(WsState.ERROR)
    }
    ws.onclose = () => {
      if (pingTimer) clearInterval(pingTimer)
      pingTimer = null
      if (socket === ws) socket = null
      setState(wanted ? WsState.DISCONNECTED : WsState.DISCONNECTED)
      scheduleReconnect()
    }
  }

  return {
    get state() {
      return state
    },
    connect() {
      wanted = true
      open()
    },
    disconnect() {
      wanted = false
      clearTimers()
      attempts = 0
      if (socket) {
        const ws = socket
        socket = null
        ws.onclose = null
        try {
          ws.close()
        } catch {
          // already closed
        }
      }
      setState(WsState.DISCONNECTED)
    },
    // Register a handler for one topic ('*' for every message). Returns the unsubscribe.
    on(topic, handler) {
      if (!handlers.has(topic)) handlers.set(topic, new Set())
      handlers.get(topic).add(handler)
      if (topic !== '*') {
        const n = (topicCounts.get(topic) || 0) + 1
        topicCounts.set(topic, n)
        if (n === 1) send({ action: 'subscribe', topics: [topic] })
      }
      return () => {
        handlers.get(topic)?.delete(handler)
        if (topic !== '*') {
          const n = (topicCounts.get(topic) || 1) - 1
          topicCounts.set(topic, n)
          if (n === 0) send({ action: 'unsubscribe', topics: [topic] })
        }
      }
    },
    onStateChange(fn) {
      stateListeners.add(fn)
      return () => stateListeners.delete(fn)
    },
    ping() {
      return send({ action: 'ping' })
    },
    send,
  }
}
