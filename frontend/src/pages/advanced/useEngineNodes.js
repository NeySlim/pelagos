// SPDX-License-Identifier: Apache-2.0
// Nodes whose modules run the given engine (all nodes when engine is falsy).
import { useMemo } from 'react'
import { useApi } from '../../hooks'
import { api } from '../../services/api'

export function useEngineNodes(engine) {
  const { data } = useApi(() => api.nodes.list().catch(() => ({ items: [] })), [])
  return useMemo(() => (data?.items || []).filter((n) => !engine || n.peer?.modules?.[engine]), [data, engine])
}
