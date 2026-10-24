// SPDX-License-Identifier: Apache-2.0
// Node id -> node name, from GET /nodes shared by every caller for a minute.
// Unknown ids (or a failed read) fall back to the id itself.
import { useCallback, useEffect, useState } from 'react'
import { api } from '../services/api'

const TTL_MS = 60000
let cache = { at: 0, names: null, pending: null }

function load() {
  if (cache.names && Date.now() - cache.at < TTL_MS) return Promise.resolve(cache.names)
  if (!cache.pending) {
    cache.pending = Promise.resolve()
      .then(() => api.nodes.list())
      .then((res) => {
        const names = {}
        for (const n of res?.items || []) {
          const peer = n.peer || n
          if (peer?.id) names[peer.id] = peer.name || peer.id
        }
        cache = { at: Date.now(), names, pending: null }
        return names
      })
      .catch(() => {
        cache = { ...cache, pending: null }
        return cache.names || {}
      })
  }
  return cache.pending
}

export function resetNodeNamesCache() {
  cache = { at: 0, names: null, pending: null }
}

export function useNodeNames(enabled = true) {
  const [names, setNames] = useState(() => cache.names || {})
  useEffect(() => {
    if (!enabled) return undefined
    let alive = true
    load().then((n) => alive && setNames(n))
    return () => {
      alive = false
    }
  }, [enabled])
  return useCallback((id) => (id ? names[id] || id : id), [names])
}
