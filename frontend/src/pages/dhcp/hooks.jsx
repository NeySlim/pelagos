// SPDX-License-Identifier: Apache-2.0
// Hooks shared by the DHCP, hosts and nodes areas: the plan flow (build a plan,
// show PlanPreview, refresh on apply) and node names.
import { useCallback, useEffect, useRef, useState } from 'react'
import { PlanPreviewModal } from '../../components/PlanPreview'
import { useNotification } from '../../contexts/NotificationContext'
import { useWsTopic } from '../../hooks/useWebSocket'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'

// Builds plans and owns the PlanPreview modal. `build(fn)` returns the plan, or
// throws when `rethrow` is set so a form can show the field errors itself.
export function usePlanFlow({ onApplied } = {}) {
  const { showError } = useNotification()
  const [plan, setPlan] = useState(null)
  const [building, setBuilding] = useState(false)
  // The last builder: "Recompute the plan" calls it again with the same inputs.
  const lastBuild = useRef(null)

  const build = useCallback(
    async (fn, { rethrow = false } = {}) => {
      setBuilding(true)
      try {
        const next = await fn()
        lastBuild.current = fn
        setPlan(next)
        return next
      } catch (err) {
        if (rethrow) throw err
        showError(errorMessage(err))
        return null
      } finally {
        setBuilding(false)
      }
    },
    [showError],
  )

  const recompute = useCallback(async () => {
    const next = await lastBuild.current()
    setPlan(next)
    return next
  }, [])

  const modal = plan ? (
    <PlanPreviewModal open onClose={() => setPlan(null)} plan={plan} onApplied={onApplied} onRolledBack={onApplied} onRecompute={recompute} />
  ) : null

  return { build, building, modal, plan, close: () => setPlan(null) }
}

// Node id to name, from GET /nodes. The list is cached for NODES_TTL_MS, a failed
// fetch is never cached, and a `nodes` WebSocket event drops the cache.
const NODES_TTL_MS = 60_000
let nodesPromise = null
let nodesFetchedAt = 0
export function resetNodeNameCache() {
  nodesPromise = null
  nodesFetchedAt = 0
}
function loadNodes() {
  if (!nodesPromise || Date.now() - nodesFetchedAt > NODES_TTL_MS) {
    nodesFetchedAt = Date.now()
    const p = api.nodes
      .list()
      .then((r) => r?.items || [])
      .catch(() => {
        if (nodesPromise === p) resetNodeNameCache()
        return []
      })
    nodesPromise = p
  }
  return nodesPromise
}
export function useNodeNames() {
  const [nodes, setNodes] = useState([])
  const [generation, setGeneration] = useState(0)
  useWsTopic('nodes', () => {
    resetNodeNameCache()
    setGeneration((g) => g + 1)
  })
  useEffect(() => {
    let alive = true
    loadNodes().then((list) => alive && setNodes(list))
    return () => {
      alive = false
    }
  }, [generation])
  const nameOf = useCallback((id) => nodes.find((n) => n.peer?.id === id)?.peer?.name || id || '-', [nodes])
  return { nodes, nameOf }
}
