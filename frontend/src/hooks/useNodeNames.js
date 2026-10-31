// SPDX-License-Identifier: Apache-2.0
// Node id -> node name (and peer), from GET /nodes shared by every caller for a minute.
// Unknown ids (or a failed read) fall back to the id itself.
import { useCallback, useEffect, useState } from 'react'
import { api } from '../services/api'

const TTL_MS = 60000
const EMPTY = { names: {}, peers: {} }
let cache = { at: 0, data: null, pending: null }

function load() {
  if (cache.data && Date.now() - cache.at < TTL_MS) return Promise.resolve(cache.data)
  if (!cache.pending) {
    cache.pending = Promise.resolve()
      .then(() => api.nodes.list())
      .then((res) => {
        const names = {}
        const peers = {}
        for (const n of res?.items || []) {
          const peer = n.peer || n
          if (!peer?.id) continue
          names[peer.id] = peer.name || peer.id
          peers[peer.id] = { id: peer.id, name: peer.name || peer.id, web_url: peer.web_url || null }
        }
        cache = { at: Date.now(), data: { names, peers }, pending: null }
        return cache.data
      })
      .catch(() => {
        cache = { ...cache, pending: null }
        return cache.data || EMPTY
      })
  }
  return cache.pending
}

export function resetNodeNamesCache() {
  cache = { at: 0, data: null, pending: null }
}

function useNodeData(enabled) {
  const [data, setData] = useState(() => cache.data || EMPTY)
  useEffect(() => {
    if (!enabled) return undefined
    let alive = true
    load().then((d) => alive && setData(d))
    return () => {
      alive = false
    }
  }, [enabled])
  return data
}

export function useNodeNames(enabled = true) {
  const { names } = useNodeData(enabled)
  return useCallback((id) => (id ? names[id] || id : id), [names])
}

// Lookup by node id or by node name: { id, name, web_url } or null while unknown.
export function useNodePeers(enabled = true) {
  const { peers } = useNodeData(enabled)
  return useCallback(
    ({ nodeId, name } = {}) => (nodeId && peers[nodeId]) || (name && Object.values(peers).find((p) => p.name === name)) || null,
    [peers],
  )
}
