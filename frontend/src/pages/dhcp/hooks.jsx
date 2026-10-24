// SPDX-License-Identifier: Apache-2.0
// Hooks shared by the DHCP, hosts and nodes areas: the plan flow (build a plan,
// show PlanPreview, refresh on apply) and node names.
import { useCallback, useEffect, useState } from 'react'
import { PlanPreviewModal } from '../../components/PlanPreview'
import { useNotification } from '../../contexts/NotificationContext'
import { api } from '../../services/api'
import { errorMessage } from '../../services/apiClient'

// Builds plans and owns the PlanPreview modal. `build(fn)` returns the plan, or
// throws when `rethrow` is set so a form can show the field errors itself.
export function usePlanFlow({ onApplied } = {}) {
  const { showError } = useNotification()
  const [plan, setPlan] = useState(null)
  const [building, setBuilding] = useState(false)

  const build = useCallback(
    async (fn, { rethrow = false } = {}) => {
      setBuilding(true)
      try {
        const next = await fn()
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

  const modal = plan ? (
    <PlanPreviewModal open onClose={() => setPlan(null)} plan={plan} onApplied={onApplied} onRolledBack={onApplied} />
  ) : null

  return { build, building, modal, plan, close: () => setPlan(null) }
}

// Node id to name, from GET /nodes, cached for the page lifetime.
let nodesPromise = null
export function resetNodeNameCache() {
  nodesPromise = null
}
export function useNodeNames() {
  const [nodes, setNodes] = useState([])
  useEffect(() => {
    let alive = true
    if (!nodesPromise) nodesPromise = api.nodes.list().then((r) => r?.items || []).catch(() => [])
    nodesPromise.then((list) => alive && setNodes(list))
    return () => {
      alive = false
    }
  }, [])
  const nameOf = useCallback((id) => nodes.find((n) => n.peer?.id === id)?.peer?.name || id || '-', [nodes])
  return { nodes, nameOf }
}

