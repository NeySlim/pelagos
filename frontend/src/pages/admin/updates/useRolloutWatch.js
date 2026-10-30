// SPDX-License-Identifier: Apache-2.0
// Follows the active rollout from the replicated state: polls GET /admin/updates/rollout, and while
// the node under the page restarts (no answer, 502 to 504) polls /health until it is back, then
// reads the rollout again. A lost session goes through the login page (AuthContext); nothing here
// depends on the page staying open.
import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../../../services/api'
import { isActive, isUnreachable } from './updatesLib'

export const POLL_MS = 2000

export function useRolloutWatch(initial, { onFinished, onReconnected, pollMs = POLL_MS } = {}) {
  const [rollout, setRollout] = useState(initial || null)
  const [connection, setConnection] = useState('ok') // ok | lost | back
  const [lostAt, setLostAt] = useState(null)
  const live = useRef(rollout)
  const conn = useRef(connection)
  const callbacks = useRef({ onFinished, onReconnected })
  callbacks.current = { onFinished, onReconnected }
  live.current = rollout
  conn.current = connection

  // A newer overview (after a plan apply or an action) replaces what the page shows.
  useEffect(() => {
    if (initial) setRollout(initial)
  }, [initial])

  const settle = useCallback(async (fresh) => {
    const before = live.current
    if (fresh) {
      setRollout(fresh)
      if (before && isActive(before) && !isActive(fresh)) callbacks.current.onFinished?.(fresh)
      return
    }
    // The rollout left `updates.rollout`: its final state is the history summary.
    if (before && isActive(before)) {
      let final = { ...before, state: 'done' }
      try {
        const page = await api.updates.history({ page: 1, per_page: 20 })
        const entry = (page?.items || []).find((h) => h.id === before.id)
        if (entry) final = { ...before, ...entry, nodes: before.nodes.map((n) => ({ ...n, ...(entry.nodes || []).find((x) => x.node_id === n.node_id) })) }
      } catch {
        // the summary is a nicety; the overview refetch below shows the versions
      }
      setRollout(final)
      callbacks.current.onFinished?.(final)
    }
  }, [])

  const tick = useCallback(async () => {
    if (conn.current === 'lost') {
      try {
        await api.meta.health()
      } catch {
        return
      }
    }
    try {
      const fresh = await api.updates.rollout()
      if (conn.current === 'lost') {
        setConnection('back')
        setLostAt(null)
        callbacks.current.onReconnected?.()
      } else if (conn.current === 'back') setConnection('ok')
      await settle(fresh)
    } catch (err) {
      if (isUnreachable(err) && conn.current !== 'lost') {
        setConnection('lost')
        setLostAt(Date.now())
      }
    }
  }, [settle])

  const watching = isActive(rollout) || connection !== 'ok'
  useEffect(() => {
    if (!watching) return undefined
    const timer = setInterval(tick, pollMs)
    return () => clearInterval(timer)
  }, [watching, tick, pollMs])

  return { rollout, setRollout, connection, lostAt, refresh: tick }
}
