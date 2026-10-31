// SPDX-License-Identifier: Apache-2.0
// One shared WebSocket for the app, connected while a session exists. Pages use
// useWsTopic(topic, handler) and never touch the socket directly.
import { createContext, useContext, useEffect, useMemo, useRef, useState, useCallback } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { createWsClient, WsState } from '../services/ws'
import { RECONNECTED_EVENT } from './useApi'

const WebSocketContext = createContext(null)

export { WsState }

export function WebSocketProvider({ children, client }) {
  const { isAuthenticated } = useAuth()
  const clientRef = useRef(client || null)
  if (!clientRef.current) clientRef.current = createWsClient()
  const [state, setState] = useState(clientRef.current.state)
  const [lastMessage, setLastMessage] = useState(null)

  useEffect(() => {
    const ws = clientRef.current
    let seen = false
    let lost = false
    const offState = ws.onStateChange((next) => {
      setState(next)
      if (next !== WsState.CONNECTED) {
        lost = seen
        return
      }
      // Back after a drop: the node may have been unreachable, so failed reads try again.
      if (lost) window.dispatchEvent(new Event(RECONNECTED_EVENT))
      seen = true
      lost = false
    })
    const offAll = ws.on('*', setLastMessage)
    return () => {
      offState()
      offAll()
    }
  }, [])

  useEffect(() => {
    const ws = clientRef.current
    if (isAuthenticated) ws.connect()
    else ws.disconnect()
    return () => ws.disconnect()
  }, [isAuthenticated])

  const subscribe = useCallback((topic, handler) => clientRef.current.on(topic, handler), [])
  const value = useMemo(
    () => ({
      state,
      isConnected: state === WsState.CONNECTED,
      lastMessage,
      subscribe,
      connect: () => clientRef.current.connect(),
      ping: () => clientRef.current.ping(),
    }),
    [state, lastMessage, subscribe],
  )

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
}

const fallback = {
  state: WsState.DISCONNECTED,
  isConnected: false,
  lastMessage: null,
  subscribe: () => () => {},
  connect: () => {},
  ping: () => false,
}

export function useWebSocket() {
  return useContext(WebSocketContext) || fallback
}

// Subscribe to a topic for the lifetime of the component; the handler may change freely.
export function useWsTopic(topic, handler) {
  const { subscribe } = useWebSocket()
  const handlerRef = useRef(handler)
  handlerRef.current = handler
  useEffect(() => {
    if (!topic) return undefined
    return subscribe(topic, (message) => handlerRef.current?.(message))
  }, [topic, subscribe])
}
